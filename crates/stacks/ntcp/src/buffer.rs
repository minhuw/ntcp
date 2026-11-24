extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};

use crate::Payload;

#[path = "send_marks.rs"]
mod send_marks;
use send_marks::SendMarks;

#[derive(Clone, Debug)]
struct SharedSpan {
    start: u64,
    payload: Payload,
}

// Per-byte metadata bits beside PUSH (bit 0) and EOR (bit 1).
// A Packet Too Big notification reported this byte's original copy dropped.
const PTB_PENDING: u8 = 1 << 2;
// A copy of this byte was (possibly) submitted again after its original.
const RETRANSMITTED: u8 = 1 << 3;
// A PTB replacement copy of this byte is outstanding and RFC 6675 SetPipe's
// HighRxt term did not count it when it was committed.
const PTB_COPY: u8 = 1 << 4;

// Up to `count` positions from `offset` of a ring of `len` whose first
// slice holds `split`, as ranges of its first and second slice.
fn ring_ranges(
    split: usize,
    len: usize,
    offset: usize,
    count: usize,
) -> [core::ops::Range<usize>; 2] {
    let start = offset.min(len);
    let end = start + count.min(len - start);
    [
        start.min(split)..end.min(split),
        start.max(split) - split..end.max(split) - split,
    ]
}

#[derive(Debug)]
pub(crate) struct SendBuffer {
    // The queued bytes and, at the same positions, their bounded PUSH/EOR
    // and PTB-pending/retransmitted bits. ACK, truncation, and resize move
    // metadata with the data. Kept apart so a segment's payload copies as
    // whole slices and its metadata scans as plain bytes.
    data: VecDeque<u8>,
    marks: SendMarks,
    capacity: usize,
    head: u64,
    shared: VecDeque<SharedSpan>,
    shared_output: Option<usize>,
    // Queue offsets immediately after the last PUSH and EOR, zero if absent.
    // A prefix ACK subtracts its byte count from both boundaries.
    push_end: usize,
    // Bytes ending at push_end known to carry only that final PUSH.
    single_push_len: usize,
    eor_end: usize,
}

impl SendBuffer {
    // Rings reserved for `capacity` queued bytes at once.
    #[cfg(test)]
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut data = VecDeque::new();
        data.try_reserve_exact(capacity).map_err(|_| ())?;
        let mut marks = SendMarks::default();
        marks.reserve(capacity)?;
        Ok(Self {
            data,
            marks,
            capacity,
            head: 0,
            shared: VecDeque::new(),
            shared_output: None,
            push_end: 0,
            single_push_len: 0,
            eor_end: 0,
        })
    }

    // A limit of `capacity` queued bytes with no ring yet: the rings are
    // allocated by `grow`, at the first write, as Linux allocates a
    // socket's skbs in sendmsg and none at socket creation.
    pub(crate) fn unallocated(capacity: usize) -> Self {
        Self {
            data: VecDeque::new(),
            marks: SendMarks::default(),
            capacity,
            head: 0,
            shared: VecDeque::new(),
            shared_output: None,
            push_end: 0,
            single_push_len: 0,
            eor_end: 0,
        }
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.data.capacity() + self.marks.capacity() + self.shared_storage_bytes()
    }

    // Queued bytes both rings hold without allocating.
    pub(crate) fn allocation_capacity(&self) -> usize {
        self.data.capacity().min(self.marks.capacity())
    }

    // The bytes `grow(capacity)` allocates: a ring that reallocates holds
    // its old storage, which storage_bytes already counts, until the new
    // one is filled, so this is also what the growth adds at its peak.
    pub(crate) fn growth_bytes(&self, capacity: usize) -> usize {
        let ring = |held: usize| if held < capacity { capacity } else { 0 };
        ring(self.data.capacity()) + ring(self.marks.capacity())
    }

    // Grows the payload and mark rings in place to hold `capacity` queued
    // bytes; the limit stays as it is. Each ring reallocates at most once and
    // moves only the shorter side of its wrap. On failure the queued bytes,
    // their marks and the limit are as they were: a ring that grew before the
    // other failed keeps its storage, which storage_bytes counts and the next
    // growth reuses.
    pub(crate) fn grow(&mut self, capacity: usize) -> Result<(), ()> {
        let additional = capacity.saturating_sub(self.data.len());
        self.data.try_reserve_exact(additional).map_err(|_| ())?;
        self.marks.reserve(capacity)
    }

    pub(crate) fn set_limit(&mut self, capacity: usize) {
        self.capacity = capacity;
    }

    // Frees the storage of an empty queue, as Linux frees an emptied write
    // queue's skbs (tcp_clean_rtx_queue, sk_wmem_free_skb): deallocation
    // only, and the next write grows the rings again. No PUSH or EOR mark
    // and no shared span is left with no byte queued; the limit and the
    // stream position stay.
    pub(crate) fn release(&mut self) {
        assert!(self.data.is_empty());
        debug_assert!(self.shared.is_empty());
        debug_assert!(self.push_end == 0 && self.eor_end == 0);
        self.data = VecDeque::new();
        self.marks = SendMarks::default();
        self.shared = VecDeque::new();
        self.push_end = 0;
        self.eor_end = 0;
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.len())
    }

    pub(crate) fn admission_room(&self, notsent: usize, lowat: Option<u32>) -> usize {
        let remaining = self.remaining();
        let Some(lowat) = lowat.filter(|&value| value != u32::MAX) else {
            return remaining;
        };
        remaining.min((lowat as usize).saturating_sub(notsent))
    }

    // The rings hold what the limit admits (`grow`, at write admission):
    // queueing never allocates.
    fn assert_reserved(&self, count: usize) {
        assert!(count <= self.data.capacity() - self.data.len());
        assert!(count <= self.marks.capacity() - self.marks.len());
    }

    pub(crate) fn append(&mut self, input: &[u8]) {
        debug_assert!(input.len() <= self.remaining());
        self.assert_reserved(input.len());
        self.data.extend(input);
        self.marks.extend_to(self.data.len());
    }

    #[cfg(test)]
    pub(crate) fn write(&mut self, input: &[u8]) -> usize {
        let count = input.len().min(self.remaining());
        self.append(&input[..count]);
        count
    }

    fn mark_slices(&self, offset: usize, count: usize) -> [&[u8]; 2] {
        debug_assert!(self.marks.singleton().is_none_or(|(_, bits)| bits == 0));
        let (front, back) = self.marks.ring.as_slices();
        let [first, second] = ring_ranges(front.len(), self.marks.ring.len(), offset, count);
        [&front[first], &back[second]]
    }

    fn mark_slices_mut(&mut self, offset: usize, count: usize) -> [&mut [u8]; 2] {
        let len = self.marks.len();
        let (front, back) = self.marks.materialize().as_mut_slices();
        let [first, second] = ring_ranges(front.len(), len, offset, count);
        [&mut front[first], &mut back[second]]
    }

    // Offset within the marks of up to `count` bytes from `offset` of the
    // first carrying `flag`. Each block is first tested whole, which needs
    // no early exit and so runs many marks per instruction.
    fn first_flagged(&self, flag: u8, offset: usize, count: usize) -> Option<usize> {
        if let Some((at, bits)) = self.marks.singleton() {
            return at
                .checked_sub(offset)
                .filter(|&distance| bits & flag != 0 && distance < count);
        }
        let mut at = 0;
        for part in self.mark_slices(offset, count) {
            for block in part.chunks(64) {
                if block.iter().fold(0, |any, mark| any | mark) & flag != 0 {
                    return block
                        .iter()
                        .position(|mark| mark & flag != 0)
                        .map(|n| at + n);
                }
                at += block.len();
            }
        }
        None
    }

    pub(crate) fn mark_push(&mut self) {
        if self.marks.or_back(1) {
            self.note_push(self.marks.len() - 1);
        }
    }

    // Offset of the last queued byte carrying PUSH.
    fn push_offset(&self) -> Option<usize> {
        self.push_end.checked_sub(1)
    }

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

    // Finds the last PUSH mark again after marks at or past it went away.
    fn find_last_push(&mut self) {
        self.push_end = self.marks.last(1).map_or(0, |offset| offset + 1);
        self.single_push_len = 1;
    }

    // Whether a byte of the range carries PUSH. Only a range ending past the
    // last mark is folded, and then only its own bytes.
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
        let [front, back] = self.mark_slices(offset, count);
        front.iter().chain(back).fold(0, |any, mark| any | mark) & 1 != 0
    }

    // Index of the first of `segments` consecutive `size`-byte ranges from
    // `offset` holding a PUSH mark. Only the ranges before the one holding
    // the last mark are scanned, in blocks folded whole (as `pushed` folds),
    // up to the first block with a mark, which smaller blocks then narrow.
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
        let mut at = 0;
        for part in self.mark_slices(offset, holding_last.min(segments) * size) {
            for block in part.chunks(4096) {
                if block.iter().fold(0, |any, mark| any | mark) & 1 != 0 {
                    for small in block.chunks(64) {
                        if small.iter().fold(0, |any, mark| any | mark) & 1 != 0 {
                            let n = small.iter().position(|mark| mark & 1 != 0).unwrap();
                            return Some((at + n) / size);
                        }
                        at += small.len();
                    }
                }
                at += block.len();
            }
        }
        (holding_last < segments).then_some(holding_last)
    }

    // Only the last byte of this nonempty range carries PUSH. Selecting
    // it leaves its persisted retransmission boundary unchanged.
    pub(crate) fn push_at_end(&self, offset: usize, count: usize) -> bool {
        count != 0
            && offset.checked_add(count) == Some(self.push_end)
            && count <= self.single_push_len
    }

    pub(crate) fn collapse_push(&mut self, offset: usize, count: usize) {
        if self.push_at_end(offset, count) {
            return;
        }
        for part in self.mark_slices_mut(offset, count) {
            for mark in part {
                *mark &= !1;
            }
        }
        let cleared = self
            .push_offset()
            .is_some_and(|last| last >= offset && last - offset < count);
        let end = offset + count - 1;
        if self.marks.or_at(end, 1) {
            self.note_push(end);
        } else if cleared {
            self.find_last_push();
        }
    }

    pub(crate) fn finish_send(&mut self, offset: usize, push: bool, end_of_record: bool) {
        let bits = u8::from(push) | (u8::from(end_of_record) << 1);
        if self.marks.or_at(offset, bits) {
            if push {
                self.note_push(offset);
            }
            if end_of_record {
                self.note_end_of_record(offset);
            }
        }
    }

    // A nonempty append puts its last byte strictly past all old marks.
    pub(crate) fn finish_append(&mut self, push: bool, end_of_record: bool) {
        if push || end_of_record {
            let end = self.len();
            let marked = self
                .marks
                .or_back(u8::from(push) | (u8::from(end_of_record) << 1));
            assert!(marked, "finish_append requires a nonempty buffer");
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
        if self.marks.or_back(2) {
            self.eor_end = self.marks.len();
        }
    }

    // Records an EOR mark at `offset`, where none is past the last one.
    // EOR marks are never cleared, so the last one moves only forward here
    // and back only when its byte goes.
    fn note_end_of_record(&mut self, offset: usize) {
        if self.eor_end <= offset {
            self.eor_end = offset + 1;
        }
    }

    // Whether the last queued byte carries EOR: the queue's tail ends a
    // record, and nothing written later joins it.
    pub(crate) fn ends_record(&self) -> bool {
        self.len() != 0 && self.record_ends_after(self.len() - 1)
    }

    // Whether a byte at or past `offset` carries EOR.
    fn record_ends_after(&self, offset: usize) -> bool {
        self.eor_end > offset
    }

    // EOR is a local coalescing boundary, not a TCP wire flag or framing
    // guarantee (RFC 9293 section 3.7.1). PUSH may collapse; EOR never does.
    // Only a selection reaching the last EOR scans its marks.
    pub(crate) fn record_len(&self, offset: usize, limit: usize) -> usize {
        self.record_len_within(offset, limit.min(self.len().saturating_sub(offset)))
    }

    // The selector already bounded this range by its unsent bytes.
    #[inline]
    pub(crate) fn record_len_within(&self, offset: usize, limit: usize) -> usize {
        debug_assert!(limit <= self.len().saturating_sub(offset));
        if !self.record_ends_after(offset) {
            return limit;
        }
        self.first_flagged(2, offset, limit)
            .map_or(limit, |n| n + 1)
    }

    // A tail rescue must contain the highest selected byte. Start after the
    // last intervening EOR, rather than clipping a prefix and losing the tail.
    pub(crate) fn tail_record_offset(&self, offset: usize, count: usize) -> usize {
        let count = count.min(self.len().saturating_sub(offset));
        if !self.record_ends_after(offset) {
            return offset;
        }
        if let Some((at, bits)) = self.marks.singleton() {
            return if bits & 2 != 0 && at >= offset && at + 1 < offset + count {
                at + 1
            } else {
                offset
            };
        }
        self.marks
            .ring
            .iter()
            .skip(offset)
            .take(count.saturating_sub(1))
            .rposition(|mark| mark & 2 != 0)
            .map_or(offset, |n| offset + n + 1)
    }

    // Mark eligible bytes (never retransmitted, not already pending) of one
    // range as PTB repair work; returns how many became pending.
    pub(crate) fn mark_ptb(&mut self, offset: usize, count: usize) -> usize {
        let mut marked = 0;
        for mark in self.mark_slices_mut(offset, count).into_iter().flatten() {
            if *mark & (PTB_PENDING | RETRANSMITTED) == 0 {
                *mark |= PTB_PENDING;
                marked += 1;
            }
        }
        marked
    }

    // Delivery or abandonment of one range: withdraw its PTB work and its
    // outstanding PTB copies. Returns (pending, copies) cleared.
    pub(crate) fn release_ptb(&mut self, offset: usize, count: usize) -> (usize, usize) {
        let (mut pending, mut copies) = (0, 0);
        for mark in self.mark_slices_mut(offset, count).into_iter().flatten() {
            pending += usize::from(*mark & PTB_PENDING != 0);
            copies += usize::from(*mark & PTB_COPY != 0);
            *mark &= !(PTB_PENDING | PTB_COPY);
        }
        (pending, copies)
    }

    // Mark an outstanding PTB copy on one range; returns how many bytes were
    // newly marked.
    pub(crate) fn mark_ptb_copy(&mut self, offset: usize, count: usize) -> usize {
        let mut marked = 0;
        for mark in self.mark_slices_mut(offset, count).into_iter().flatten() {
            marked += usize::from(*mark & PTB_COPY == 0);
            *mark |= PTB_COPY;
        }
        marked
    }

    // HighRxt moved over one range: SetPipe's retransmission term now counts
    // its outstanding PTB copies. Returns how many marks were cleared.
    pub(crate) fn clear_ptb_copy(&mut self, offset: usize, count: usize) -> usize {
        let mut cleared = 0;
        for mark in self.mark_slices_mut(offset, count).into_iter().flatten() {
            cleared += usize::from(*mark & PTB_COPY != 0);
            *mark &= !PTB_COPY;
        }
        cleared
    }

    // Record a (possibly) submitted retransmitted copy: those bytes lose any
    // PTB work and never become eligible again. Returns the pending bytes it
    // withdrew.
    pub(crate) fn mark_retransmitted(&mut self, offset: usize, count: usize) -> usize {
        let mut cleared = 0;
        for mark in self.mark_slices_mut(offset, count).into_iter().flatten() {
            cleared += usize::from(*mark & PTB_PENDING != 0);
            *mark = (*mark & !PTB_PENDING) | RETRANSMITTED;
        }
        cleared
    }

    // First contiguous run of PTB work in [offset, end): (offset, length),
    // its length counted to at most `limit`.
    pub(crate) fn next_ptb(
        &self,
        offset: usize,
        end: usize,
        limit: usize,
    ) -> Option<(usize, usize)> {
        self.next_flagged(PTB_PENDING, offset, end, limit)
    }

    // First contiguous run of outstanding PTB copies in [offset, end).
    pub(crate) fn next_ptb_copy(&self, offset: usize, end: usize) -> Option<(usize, usize)> {
        self.next_flagged(PTB_COPY, offset, end, usize::MAX)
    }

    fn next_flagged(
        &self,
        flag: u8,
        offset: usize,
        end: usize,
        limit: usize,
    ) -> Option<(usize, usize)> {
        debug_assert_eq!(flag & 0b11, 0);
        let end = end.min(self.marks.ring.len());
        let start = (offset..end).find(|&i| self.marks.ring[i] & flag != 0)?;
        let len = self
            .marks
            .ring
            .range(start..end)
            .take(limit)
            .take_while(|&byte| byte & flag != 0)
            .count();
        Some((start, len))
    }

    // Bytes of one range that carry PTB work.
    pub(crate) fn count_ptb(&self, offset: usize, count: usize) -> usize {
        self.marks
            .ring
            .range(offset.min(self.marks.ring.len())..)
            .take(count)
            .filter(|&byte| byte & PTB_PENDING != 0)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn ptb_pending(&self, offset: usize) -> bool {
        self.marks
            .ring
            .get(offset)
            .is_some_and(|&byte| byte & PTB_PENDING != 0)
    }

    #[cfg(test)]
    pub(crate) fn ptb_copy(&self, offset: usize) -> bool {
        self.marks
            .ring
            .get(offset)
            .is_some_and(|&byte| byte & PTB_COPY != 0)
    }

    #[cfg(test)]
    pub(crate) fn retransmitted(&self, offset: usize) -> bool {
        self.marks
            .ring
            .get(offset)
            .is_some_and(|&byte| byte & RETRANSMITTED != 0)
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
        self.marks.truncate(len);
        // Discarding queued bytes is rare; only then is the queue searched
        // back to its new last mark.
        if self.push_end > len {
            self.find_last_push();
        }
        if self.eor_end > len {
            self.eor_end = self.marks.last(2).map_or(0, |offset| offset + 1);
        }
        while self
            .shared
            .back()
            .is_some_and(|span| span.start.wrapping_sub(self.head) as usize >= len)
        {
            self.shared.pop_back();
        }
        if let Some(span) = self.shared.back_mut() {
            let start = span.start.wrapping_sub(self.head) as usize;
            let keep = span.payload.len().min(len.saturating_sub(start));
            span.payload = span.payload.slice(0..keep).unwrap();
        }
    }

    // Storage only: the caller validates SEG.ACK and converts its advance into a data-byte
    // count.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    pub(crate) fn acknowledge(&mut self, count: usize) -> Result<(), ()> {
        if count > self.len() {
            return Err(());
        }
        if count == self.len() {
            self.data.clear();
            self.marks.clear();
            self.shared.clear();
            self.head = self.head.wrapping_add(count as u64);
            self.push_end = 0;
            self.eor_end = 0;
            return Ok(());
        }
        self.data.drain(..count);
        self.marks.drop_prefix(count);
        self.head = self.head.wrapping_add(count as u64);
        self.push_end = self.push_end.saturating_sub(count);
        self.eor_end = self.eor_end.saturating_sub(count);
        while let Some(span) = self.shared.front_mut() {
            let consumed = self.head.wrapping_sub(span.start) as usize;
            if consumed >= 1usize << (usize::BITS - 1) {
                break;
            }
            if consumed >= span.payload.len() {
                self.shared.pop_front();
            } else {
                span.start = self.head;
                span.payload = span.payload.slice(consumed..span.payload.len()).unwrap();
                break;
            }
        }
        Ok(())
    }

    // Borrow a scalar payload directly when the selected bytes all come
    // from one slice of the ring. Shared spans overlay the ring's bytes.
    pub(crate) fn contiguous(&self, offset: usize, limit: usize) -> Option<&[u8]> {
        self.selected_slice(offset, self.record_len(offset, limit))
    }

    // The caller has already clipped these bytes to the record boundary.
    pub(crate) fn selected_slice(&self, offset: usize, count: usize) -> Option<&[u8]> {
        debug_assert_eq!(self.record_len(offset, count), count);
        if !self.shared.is_empty() {
            return None;
        }
        let (front, back) = self.data.as_slices();
        if offset < front.len() {
            front.get(offset..offset + count)
        } else {
            let start = offset - front.len();
            back.get(start..start + count)
        }
    }

    pub(crate) fn copy(&self, offset: usize, out: &mut [u8]) -> usize {
        let count = self.selection_len(offset, self.record_len(offset, out.len()));
        if self.shared_output.is_some()
            && self.shared_prefix(offset, count, usize::MAX) == count
            && count != 0
        {
            return count;
        }
        let (front, back) = self.data.as_slices();
        let [first, second] = ring_ranges(front.len(), self.data.len(), offset, count);
        let split = first.len();
        out[..split].copy_from_slice(&front[first]);
        out[split..count].copy_from_slice(&back[second]);
        for span in &self.shared {
            let start = span.start.wrapping_sub(self.head) as usize;
            let left = start.max(offset);
            let right = (start + span.payload.len()).min(offset + count);
            if left < right {
                out[left - offset..right - offset]
                    .copy_from_slice(&span.payload.as_slice()[left - start..right - start]);
            }
        }
        count
    }

    #[cfg(test)]
    pub(crate) fn shared_spans(&self) -> usize {
        self.shared.len()
    }

    // Whether `payload` fits beside at most `max_spans` spans: it joins the
    // last one or fewer are held.
    pub(crate) fn shared_room(&self, payload: &Payload, max_spans: usize) -> bool {
        self.shared.len() < max_spans || self.joined(payload).is_some()
    }

    pub(crate) fn shared_storage_bytes(&self) -> usize {
        self.shared.capacity() * core::mem::size_of::<SharedSpan>()
    }

    pub(crate) fn prepare_shared(&mut self, payload: &Payload, peak_room: usize) -> Result<(), ()> {
        if self.shared.len() < self.shared.capacity() || self.joined(payload).is_some() {
            return Ok(());
        }
        let needed = self.shared.len().checked_add(1).ok_or(())?;
        let bound = needed
            .checked_next_power_of_two()
            .ok_or(())?
            .checked_mul(core::mem::size_of::<SharedSpan>())
            .ok_or(())?;
        if bound > peak_room {
            return Err(());
        }
        let mut staged = VecDeque::new();
        staged.try_reserve_exact(needed).map_err(|_| ())?;
        if staged.capacity() * core::mem::size_of::<SharedSpan>() > peak_room {
            return Err(());
        }
        staged.extend(self.shared.iter().cloned());
        self.shared = staged;
        Ok(())
    }

    pub(crate) fn write_shared(&mut self, payload: Payload) -> usize {
        let count = payload.len().min(self.remaining());
        if count == 0 {
            return 0;
        }
        self.assert_reserved(count);
        let payload = payload.slice(0..count).unwrap();
        if let Some(joined) = self.joined(&payload) {
            self.shared.back_mut().unwrap().payload = joined;
        } else {
            assert!(self.shared.len() < self.shared.capacity());
            let start = self.head.wrapping_add(self.data.len() as u64);
            self.shared.push_back(SharedSpan { start, payload });
        }
        // Only PUSH/EOR bookkeeping is initialized. Payload remains in its
        // original immutable allocation and is never read/copied here.
        self.data.resize(self.data.len() + count, 0);
        self.marks.extend_to(self.data.len());
        count
    }

    // The last span extended by `payload` when it ends where the queue does
    // and `payload` continues it in the same storage and lease, as Linux
    // coalesces adjacent zerocopy fragments: contiguous writes then cost one
    // span, not one per write.
    fn joined(&self, payload: &Payload) -> Option<Payload> {
        let span = self.shared.back()?;
        let end = span.start.wrapping_add(span.payload.len() as u64);
        if end != self.head.wrapping_add(self.data.len() as u64) {
            return None;
        }
        span.payload.join(payload)
    }

    pub(crate) fn set_shared_output(&mut self, segments: Option<usize>) {
        self.shared_output = segments;
    }

    fn shared_prefix(&self, offset: usize, count: usize, max_segments: usize) -> usize {
        let mut at = offset;
        let mut used = 0;
        for span in &self.shared {
            let start = span.start.wrapping_sub(self.head) as usize;
            let end = start + span.payload.len();
            if end <= at {
                continue;
            }
            if start > at || used == max_segments {
                break;
            }
            let n = (end - at).min(count - (at - offset));
            at += n;
            used += 1;
            if at - offset == count {
                break;
            }
        }
        at - offset
    }

    pub(crate) fn selection_len(&self, offset: usize, count: usize) -> usize {
        let Some(max) = self.shared_output else {
            return count;
        };
        let shared = self.shared_prefix(offset, count, max);
        if shared != 0 {
            return shared;
        }
        self.shared
            .iter()
            .map(|s| s.start.wrapping_sub(self.head) as usize)
            .find(|&start| start > offset)
            .map_or(count, |start| count.min(start - offset))
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
        let mut at = offset;
        for span in &self.shared {
            let start = span.start.wrapping_sub(self.head) as usize;
            let end = start + span.payload.len();
            if end <= at {
                continue;
            }
            let n = (end - at).min(count - (at - offset));
            out.push(span.payload.slice(at - start..at - start + n).unwrap());
            at += n;
            if at - offset == count {
                break;
            }
        }
        true
    }

    pub(crate) fn release_shared(&mut self) {
        self.shared.clear();
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

    #[test]
    fn send_shrink_saturates_and_failed_growth_preserves_data() {
        let mut send = SendBuffer::new(8).unwrap();
        send.write(b"abcdef");
        send.mark_push();
        send.set_limit(2);
        assert_eq!(send.remaining(), 0);
        assert_eq!(send.write(b"!"), 0);
        assert!(send.grow(usize::MAX).is_err());
        send.grow(16).unwrap();
        send.set_limit(16);
        let mut grown = send;
        let mut out = [0; 6];
        assert_eq!(grown.copy(0, &mut out), 6);
        assert_eq!(&out, b"abcdef");
        assert!(grown.pushed(0, 6));
        grown.acknowledge(5).unwrap();
        grown.set_limit(2);
        assert_eq!(grown.write(b"xy"), 1);
    }

    use super::*;

    #[test]
    // Checks prefix removal by byte count, not wire ACK validation.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    fn send_retains_partial_copy_and_acknowledges_without_growth() {
        let mut send = SendBuffer::new(4).unwrap();
        assert_eq!(send.capacity(), 4);
        assert_eq!(send.remaining(), 4);
        assert_eq!(send.write(b"abcdef"), 4);
        assert_eq!(send.write(b"x"), 0);
        assert_eq!(send.acknowledge(5), Err(()));
        let mut out = [b'!'; 6];
        assert_eq!(send.copy(1, &mut out), 3);
        assert_eq!(&out, b"bcd!!!");
        assert_eq!(send.copy(usize::MAX, &mut out), 0);
        assert_eq!(send.len(), 4);
        assert_eq!(send.acknowledge(2), Ok(()));
        assert_eq!(send.write(b"efg"), 2);
        assert_eq!(send.copy(0, &mut out[..4]), 4);
        assert_eq!(&out[..4], b"cdef");
        assert_eq!(send.acknowledge(4), Ok(()));
        assert_eq!(send.acknowledge(0), Ok(()));
        assert_eq!(send.remaining(), 4);
        let mut empty = SendBuffer::new(0).unwrap();
        assert_eq!(empty.write(b"a"), 0);
        assert!(SendBuffer::new(usize::MAX).is_err());
    }

    #[test]
    fn send_payload_and_marks_match_a_byte_model_across_wrap() {
        // Payload and marks live in separate rings: their slices, the
        // block scans and the clamping must agree with one (byte, mark)
        // sequence while the rings wrap.
        let mut send = SendBuffer::new(300).unwrap();
        let mut model: VecDeque<(u8, u8)> = VecDeque::new();
        let mut state = 0x9e37_79b9_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        let mut out = [0; 400];
        for step in 0..4000 {
            match next(7) {
                0 | 1 => {
                    let len = next(200);
                    let input: Vec<u8> = (0..len).map(|i| (step + i) as u8).collect();
                    let count = send.write(&input);
                    assert_eq!(count, len.min(300 - model.len()));
                    model.extend(input[..count].iter().map(|&b| (b, 0)));
                }
                2 => {
                    send.mark_push();
                    send.mark_end_of_record();
                    if let Some(last) = model.back_mut() {
                        last.1 |= 3;
                    }
                }
                3 => {
                    let count = next(model.len() + 1);
                    send.acknowledge(count).unwrap();
                    model.drain(..count);
                }
                4 if !model.is_empty() => {
                    let offset = next(model.len());
                    let count = 1 + next(model.len() - offset);
                    send.collapse_push(offset, count);
                    for mark in model.range_mut(offset..offset + count) {
                        mark.1 &= !1;
                    }
                    model[offset + count - 1].1 |= 1;
                }
                5 => {
                    let len = next(model.len() + 1);
                    send.truncate(len);
                    model.truncate(len);
                }
                _ => {
                    let offset = next(model.len() + 1);
                    let (push, end_of_record) = (next(2) == 0, next(4) == 0);
                    send.finish_send(offset, push, end_of_record);
                    if let Some(mark) = model.get_mut(offset) {
                        mark.1 |= u8::from(push) | u8::from(end_of_record) << 1;
                    }
                }
            }
            let offset = next(model.len() + 2);
            let limit = next(out.len() + 1);
            let tail: Vec<(u8, u8)> = model.iter().skip(offset).take(limit).copied().collect();
            let record = tail
                .iter()
                .position(|byte| byte.1 & 2 != 0)
                .map_or(tail.len(), |n| n + 1);
            assert_eq!(send.record_len(offset, limit), record);
            assert_eq!(
                send.pushed(offset, limit),
                tail.iter().any(|byte| byte.1 & 1 != 0)
            );
            assert_eq!(
                send.pushed(offset, model.len().saturating_sub(offset)),
                model.iter().skip(offset).any(|byte| byte.1 & 1 != 0)
            );
            assert_eq!(send.copy(offset, &mut out[..limit]), record);
            assert!(
                out[..record]
                    .iter()
                    .eq(tail[..record].iter().map(|byte| &byte.0))
            );
            match send.contiguous(offset, limit) {
                Some(slice) => assert_eq!(slice, &out[..record]),
                None => {
                    let (front, back) = send.data.as_slices();
                    assert!(
                        offset < front.len() && offset + record > front.len()
                            || offset >= front.len() && offset - front.len() + record > back.len(),
                        "contiguous returned None without spanning ring wrap"
                    );
                }
            }
        }
    }

    #[test]
    fn first_pushed_segment_agrees_with_a_byte_model_across_wrap() {
        // Segments of queued bytes, the PUSH marks of writes and ACKs that
        // move the ring's head around it: the first segment holding a mark
        // is the model's, whichever block of the scan it falls in.
        let mut send = SendBuffer::new(20_000).unwrap();
        let mut model: VecDeque<bool> = VecDeque::new();
        let mut state = 0x9e37_79b9_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        for _ in 0..3000 {
            if next(3) == 0 && !model.is_empty() {
                let count = next(model.len() + 1);
                send.acknowledge(count).unwrap();
                model.drain(..count);
            } else {
                let count = send.write(&[7; 6000][..next(6001)]);
                model.extend(core::iter::repeat_n(false, count));
                if count != 0 && next(2) == 0 {
                    send.mark_push();
                    *model.back_mut().unwrap() = true;
                }
            }
            let size = 1 + next(1500);
            let offset = next(model.len() + 1);
            let segments = next((model.len() - offset) / size + 1);
            let expected = (0..segments).find(|&n| {
                model
                    .range(offset + n * size..offset + (n + 1) * size)
                    .any(|&push| push)
            });
            assert_eq!(
                send.first_pushed_segment(offset, size, segments),
                expected,
                "offset {offset} size {size} segments {segments}"
            );
        }
    }

    #[test]
    fn record_ends_follow_the_last_eor_across_ack_truncate_and_wrap() {
        // record_len and tail_record_offset skip their scan past the last
        // EOR: both must agree with a byte model of the EOR marks whatever
        // writes, marks, ACKs and truncations moved it.
        let mut send = SendBuffer::new(300).unwrap();
        let mut model: VecDeque<bool> = VecDeque::new();
        let mut state = 0x2545_f491_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        for _ in 0..4000 {
            match next(6) {
                0 | 1 => {
                    let count = send.write(&[7; 64][..next(65)]);
                    model.extend(core::iter::repeat_n(false, count));
                }
                2 => {
                    send.mark_end_of_record();
                    if let Some(last) = model.back_mut() {
                        *last = true;
                    }
                }
                3 => {
                    let count = next(model.len() + 1);
                    send.acknowledge(count).unwrap();
                    model.drain(..count);
                }
                4 => {
                    let len = next(model.len() + 1);
                    send.truncate(len);
                    model.truncate(len);
                }
                _ => {
                    let offset = next(model.len() + 1);
                    send.finish_send(offset, false, true);
                    if let Some(mark) = model.get_mut(offset) {
                        *mark = true;
                    }
                }
            }
            let offset = next(model.len() + 2);
            let limit = next(400);
            let tail: Vec<bool> = model.iter().skip(offset).take(limit).copied().collect();
            assert_eq!(
                send.record_len(offset, limit),
                tail.iter()
                    .position(|&eor| eor)
                    .map_or(tail.len(), |n| n + 1)
            );
            assert_eq!(
                send.tail_record_offset(offset, limit),
                tail.iter()
                    .take(tail.len().saturating_sub(1))
                    .rposition(|&eor| eor)
                    .map_or(offset, |n| offset + n + 1)
            );
        }
    }

    #[test]
    fn eor_survives_push_collapse_resize_ack_and_truncate_without_growth() {
        let mut send = SendBuffer::new(8).unwrap();
        let charge = send.storage_bytes();
        send.write(b"abc");
        send.mark_end_of_record();
        send.mark_push();
        send.write(b"defgh");
        send.mark_end_of_record();
        send.collapse_push(0, 5); // PUSH collapse never moves EOR.
        assert_eq!(send.record_len(0, 8), 3);
        assert_eq!(send.tail_record_offset(0, 8), 3);
        assert_eq!(send.tail_record_offset(0, 3), 0);
        let mut bytes = [0; 8];
        assert_eq!(send.copy(0, &mut bytes), 3);
        assert_eq!(&bytes[..3], b"abc");
        assert_eq!(send.storage_bytes(), charge);
        send.grow(16).unwrap();
        send.set_limit(16);
        send.acknowledge(2).unwrap();
        assert_eq!(send.copy(0, &mut bytes), 1);
        assert_eq!(bytes[0], b'c');
        send.acknowledge(1).unwrap();
        send.truncate(3); // Discarded EOR cannot affect later writes.
        send.write(b"ij");
        assert_eq!(send.copy(0, &mut bytes), 5);
        assert_eq!(&bytes[..5], b"defij");
    }
    #[test]
    fn lowat_byte_admission_preserves_capacity_across_resize_discard_and_ack() {
        for capacity in [0, 1, 6, 16384, 32768, 65536] {
            let mut send = SendBuffer::new(capacity).unwrap();
            let charge = send.storage_bytes();
            assert_eq!(send.admission_room(0, Some(0)), 0);
            assert_eq!(send.admission_room(0, None), capacity);
            assert_eq!(send.admission_room(0, Some(u32::MAX)), capacity);
            send.write(&alloc::vec![1; capacity.min(3)]);
            for notsent in [0, 3, 4, 5, usize::MAX] {
                assert_eq!(
                    send.admission_room(notsent, Some(4)),
                    send.remaining().min(4usize.saturating_sub(notsent))
                );
            }
            assert_eq!(send.storage_bytes(), charge);
        }
        let mut send = SendBuffer::new(32).unwrap();
        send.write(&[1; 8]);
        send.mark_end_of_record();
        send.mark_push();
        assert_eq!(send.admission_room(8, Some(10)), 2);
        send.grow(64).unwrap();
        send.set_limit(64);
        assert_eq!(send.admission_room(8, Some(10)), 2);
        send.truncate(5);
        assert_eq!(send.admission_room(5, Some(10)), 5);
        send.set_limit(6);
        assert_eq!(send.admission_room(5, Some(10)), 1);
        send.set_limit(4);
        assert_eq!(send.admission_room(5, Some(10)), 0);
        send.acknowledge(5).unwrap();
        assert_eq!(send.admission_room(0, Some(10)), 4);
    }

    #[test]
    fn send_growth_in_place_keeps_bytes_and_marks_across_wraps() {
        let mut state = 0x9e37_79b9_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        let mut send = SendBuffer::new(32).unwrap();
        let mut model: VecDeque<(u8, u8)> = VecDeque::new();
        let (mut wrapped, mut released) = (0, 0);
        for step in 0..4000 {
            match next(5) {
                0 | 1 => {
                    let input: Vec<u8> = (0..next(100)).map(|i| (step + i) as u8).collect();
                    // As Connection::send_ring_target: double, within the
                    // limit, before queueing.
                    let live = (model.len() + input.len()).min(send.capacity());
                    if live > send.allocation_capacity() {
                        let ring = live
                            .max(2 * send.allocation_capacity())
                            .next_power_of_two()
                            .min(send.capacity());
                        send.grow(ring).unwrap();
                    }
                    let count = send.write(&input);
                    assert_eq!(count, input.len().min(send.capacity() - model.len()));
                    model.extend(input[..count].iter().map(|&b| (b, 0)));
                }
                2 => {
                    // Sometimes everything, so that the queue drains.
                    let count = if next(4) == 0 {
                        model.len()
                    } else {
                        next(model.len() + 1)
                    };
                    send.acknowledge(count).unwrap();
                    model.drain(..count);
                    // A drained queue may free its rings.
                    if model.is_empty() && next(2) == 0 {
                        send.release();
                        assert_eq!(send.storage_bytes(), 0);
                        released += 1;
                    }
                }
                3 if !model.is_empty() => {
                    let offset = next(model.len());
                    let (push, end_of_record) = (next(2) == 0, next(3) == 0);
                    send.finish_send(offset, push, end_of_record);
                    model[offset].1 |= u8::from(push) | u8::from(end_of_record) << 1;
                    let count = 1 + next(model.len() - offset);
                    send.mark_ptb(offset, count);
                    for mark in model.range_mut(offset..offset + count) {
                        if mark.1 & (PTB_PENDING | RETRANSMITTED) == 0 {
                            mark.1 |= PTB_PENDING;
                        }
                    }
                }
                4 if next(4) == 0 && send.capacity() < 2048 => {
                    wrapped += usize::from(!send.data.as_slices().1.is_empty());
                    let capacity = send.capacity() + 1 + next(16);
                    send.grow(capacity).unwrap();
                    assert!(send.allocation_capacity() >= capacity);
                    assert!(send.marks.capacity() >= capacity);
                    send.set_limit(capacity);
                }
                _ => {}
            }
            assert!(send.data.iter().copied().eq(model.iter().map(|b| b.0)));
            assert!(send.marks.iter().copied().eq(model.iter().map(|b| b.1)));
            if !model.is_empty() {
                let offset = next(model.len());
                let count = 1 + next(model.len() - offset);
                let range = model.range(offset..offset + count);
                assert_eq!(
                    send.pushed(offset, count),
                    range.clone().any(|b| b.1 & 1 != 0)
                );
                assert_eq!(
                    send.record_len(offset, count),
                    range
                        .clone()
                        .position(|b| b.1 & 2 != 0)
                        .map_or(count, |n| n + 1)
                );
            }
        }
        assert!(wrapped > 20 && released > 20, "{wrapped} {released}");
    }

    // Releasing an empty queue's storage keeps its limit and stream
    // position and leaves no PUSH, EOR or shared span behind: the regrown
    // ring marks, finds and copies its new bytes as a fresh one would.
    #[test]
    fn release_and_regrowth_keep_marks_positions_and_spans() {
        let mut send = SendBuffer::new(16).unwrap();
        send.write(&[1; 12]);
        send.acknowledge(8).unwrap();
        send.write(b"abcdefghij");
        send.mark_end_of_record();
        send.mark_push();
        send.finish_send(2, true, true);
        send.mark_ptb(0, 14);
        assert!(send.pushed(13, 1) && send.record_len(0, 14) == 3);
        send.acknowledge(14).unwrap();
        send.release();
        assert_eq!((send.storage_bytes(), send.allocation_capacity()), (0, 0));
        assert_eq!((send.capacity(), send.remaining()), (16, 16));
        send.grow(8).unwrap();
        assert_eq!(send.write(b"xyz"), 3);
        assert!(!send.pushed(0, 3) && !send.ptb_pending(0) && !send.retransmitted(0));
        assert_eq!(send.record_len(0, 8), 3);
        assert_eq!(send.tail_record_offset(0, 3), 0);
        send.finish_send(0, false, true);
        send.mark_push();
        assert!(send.pushed(2, 1) && !send.pushed(0, 2));
        assert_eq!(send.record_len(0, 8), 1);
        send.acknowledge(1).unwrap();
        assert!(send.pushed(0, 2) && send.record_len(0, 8) == 2);
        let mut out = [0; 8];
        assert_eq!(send.copy(0, &mut out), 2);
        assert_eq!(&out[..2], b"yz");
        // Shared spans start at the stream position the queue reached.
        send.set_shared_output(Some(4));
        let payload = Payload::from_vec(alloc::vec![7; 5]);
        send.acknowledge(2).unwrap();
        send.release();
        send.grow(8).unwrap();
        send.prepare_shared(&payload, usize::MAX).unwrap();
        assert_eq!(send.write_shared(payload.clone()), 5);
        let mut parts = Vec::with_capacity(4);
        assert!(send.shared_slices(0, 5, &mut parts));
        assert_eq!(parts[0].as_slice(), &[7; 5]);
        send.acknowledge(5).unwrap();
        assert_eq!(send.shared_spans(), 0);
        send.release();
        assert_eq!(send.storage_bytes(), 0);
        send.grow(8).unwrap();
        send.prepare_shared(&payload, usize::MAX).unwrap();
        assert_eq!(send.write_shared(payload), 5);
        assert_eq!(send.copy(0, &mut out), 5);
        assert!(send.shared_slices(0, 5, &mut Vec::with_capacity(4)));
    }

    #[test]
    fn failed_send_growth_leaves_the_ring_unchanged_and_retry_reuses_storage() {
        use crate::allocation_tests::fail_after;
        let mut send = SendBuffer::new(16).unwrap();
        send.write(&[1; 12]);
        send.acknowledge(8).unwrap();
        send.write(b"abcdefghij");
        send.mark_push();
        assert!(!send.data.as_slices().1.is_empty());
        let before = (send.data.clone(), send.marks.clone(), send.capacity());
        let storage = send.storage_bytes();
        assert_eq!(fail_after(0, || send.grow(64)), Err(()));
        assert_eq!(send.storage_bytes(), storage);
        assert_eq!(fail_after(1, || send.grow(64)), Err(()));
        assert_eq!(
            (send.data.clone(), send.marks.clone(), send.capacity()),
            before
        );
        assert!(send.storage_bytes() >= storage + 48);
        assert!(fail_after(0, || send.grow(16) == Ok(()) && SendBuffer::new(1).is_err()));
        // Only the marks are left to reserve.
        assert_eq!(fail_after(1, || send.grow(64)), Ok(()));
        assert_eq!(
            (send.data.clone(), send.marks.clone(), send.capacity()),
            before
        );
        send.set_limit(64);
        assert_eq!(send.write(&[2; 60]), 50);
        let mut out = [0; 64];
        assert_eq!(send.copy(0, &mut out), 64);
        assert_eq!(&out[..14], b"\x01\x01\x01\x01abcdefghij");
        assert!(send.pushed(13, 1) && !send.pushed(0, 13));
    }

    #[test]
    fn collapse_push_early_return_and_contiguous_ring_wrap_and_shared() {
        let mut send = SendBuffer::new(16).unwrap();
        // Single PUSH at index 5 -> single_push_len == 6.
        assert_eq!(send.write(b"abcdef"), 6);
        send.mark_push();
        assert_eq!(send.single_push_len, 6);
        // count == single_push_len takes the early return without altering marks.
        send.collapse_push(0, 6);
        assert!(send.pushed(5, 1) && !send.pushed(0, 5));

        // Adding an earlier PUSH via finish_send narrows single_push_len to 5 - 2 = 3.
        send.finish_send(2, true, false);
        assert_eq!(send.single_push_len, 3);
        // count == 3 (indices 3..=5) early-returns and leaves earlier PUSH at 2 intact.
        send.collapse_push(3, 3);
        assert!(send.pushed(2, 1) && send.pushed(5, 1) && !send.pushed(3, 2));
        // count == 4 (indices 2..=5) > single_push_len clears the earlier PUSH at 2.
        send.collapse_push(2, 4);
        assert!(!send.pushed(0, 5) && send.pushed(5, 1));

        // After acknowledge keeping last_push, collapse_push still preserves correctness.
        send.acknowledge(3).unwrap(); // remaining: "def" with PUSH at index 2
        send.finish_send(0, true, false); // PUSH at 0 and 2 -> single_push_len = 2
        send.collapse_push(1, 2); // early return on 1..=2
        assert!(send.pushed(0, 1) && send.pushed(2, 1));
        send.collapse_push(0, 3); // clears PUSH at 0
        assert!(!send.pushed(0, 2) && send.pushed(2, 1));

        // After truncate drops last_push, find_last_push resets single_push_len = 1.
        send.finish_send(0, true, false);
        send.truncate(2); // remaining: "de" with PUSH at 0
        assert_eq!(send.single_push_len, 1);
        send.collapse_push(0, 1);
        assert!(send.pushed(0, 1) && !send.pushed(1, 1));

        // After release + grow, single_push_len works cleanly for new writes.
        send.acknowledge(2).unwrap();
        send.release();
        send.grow(16).unwrap();

        // Force a ring wrap: write 12, ack 10, write 10 -> front has 6 bytes, back has 6 bytes
        // (exact split depends on VecDeque capacity, so verify wrap explicitly).
        assert_eq!(send.write(b"0123456789ab"), 12);
        send.acknowledge(10).unwrap();
        assert_eq!(send.write(b"ABCDEFGHIJ"), 10);
        let (front, back) = send.data.as_slices();
        assert!(
            !front.is_empty() && !back.is_empty(),
            "expected wrapped ring"
        );
        let (front_len, back_len, first_byte) = (front.len(), back.len(), front[0]);
        let mut out = [0; 16];
        // Front-only slice returns Some matching copy.
        let front_slice = send.contiguous(0, front_len).unwrap();
        let n = send.copy(0, &mut out[..front_len]);
        assert_eq!(front_slice, &out[..n]);
        // Back-only slice returns Some matching copy.
        let back_slice = send.contiguous(front_len, back_len).unwrap();
        let n = send.copy(front_len, &mut out[..back_len]);
        assert_eq!(back_slice, &out[..n]);
        // Selection spanning front..back returns None, while copy still succeeds.
        assert!(send.contiguous(front_len - 1, 2).is_none());
        assert_eq!(send.copy(front_len - 1, &mut out[..2]), 2);
        // EOR inside the front slice limits contiguous to the record end.
        send.finish_send(0, false, true);
        assert_eq!(send.contiguous(0, send.len()), Some(&[first_byte][..]));

        // Non-empty shared payloads must make contiguous return None.
        send.set_shared_output(Some(4));
        let payload = Payload::from_vec(alloc::vec![b'Z'; 4]);
        send.prepare_shared(&payload, usize::MAX).unwrap();
        assert_eq!(send.write_shared(payload), 4);
        assert!(send.contiguous(0, 1).is_none());
        assert!(send.contiguous(send.len() - 4, 4).is_none());
    }

    #[test]
    fn send_marks_and_buffer_operations_match_vecdeque_oracle() {
        let mut send = SendBuffer::new(256).unwrap();
        let mut oracle: VecDeque<u8> = VecDeque::new();
        let mut state = 0x7319_a5c1_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };

        let mut saw_singleton_push = false;
        let mut saw_singleton_eor = false;
        let mut saw_materialized = false;
        let mut saw_full_ack_return_to_singleton = false;
        let mut saw_ptb = false;

        for step in 0..6000 {
            let was_materialized = send.marks.singleton().is_none();
            match next(14) {
                0..=2 => {
                    // Nonempty append + optional finish_append.
                    let room = send.remaining();
                    if room != 0 {
                        let len = 1 + next(room.min(48));
                        let input: Vec<u8> = (0..len).map(|i| (step + i) as u8).collect();
                        send.append(&input);
                        oracle.extend(core::iter::repeat_n(0u8, len));
                        let push = next(3) == 0;
                        let eor = next(4) == 0;
                        send.finish_append(push, eor);
                        if push || eor {
                            *oracle.back_mut().unwrap() |= u8::from(push) | (u8::from(eor) << 1);
                        }
                    }
                }
                3 => {
                    send.mark_push();
                    if let Some(last) = oracle.back_mut() {
                        *last |= 1;
                    }
                }
                4 => {
                    send.mark_end_of_record();
                    if let Some(last) = oracle.back_mut() {
                        *last |= 2;
                    }
                }
                5 if !oracle.is_empty() => {
                    let offset = next(oracle.len());
                    let count = 1 + next(oracle.len() - offset);
                    send.collapse_push(offset, count);
                    for mark in oracle.range_mut(offset..offset + count) {
                        *mark &= !1;
                    }
                    oracle[offset + count - 1] |= 1;
                }
                6 => {
                    let offset = next(oracle.len() + 2);
                    let push = next(2) == 0;
                    let eor = next(3) == 0;
                    send.finish_send(offset, push, eor);
                    if let Some(mark) = oracle.get_mut(offset) {
                        *mark |= u8::from(push) | (u8::from(eor) << 1);
                    }
                }
                7 => {
                    // Full ACK back to singleton, or partial ACK.
                    let count = if next(3) == 0 {
                        oracle.len()
                    } else {
                        next(oracle.len() + 1)
                    };
                    send.acknowledge(count).unwrap();
                    oracle.drain(..count);
                    if was_materialized && count > 0 && oracle.is_empty() {
                        assert!(send.marks.singleton().is_some());
                        saw_full_ack_return_to_singleton = true;
                    }
                }
                8 => {
                    let len = next(oracle.len() + 1);
                    send.truncate(len);
                    oracle.truncate(len);
                }
                9 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let end = (offset + count).min(oracle.len());
                    let start = offset.min(oracle.len());
                    let mut expected = 0;
                    for m in oracle.range_mut(start..end) {
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
                10 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let end = (offset + count).min(oracle.len());
                    let start = offset.min(oracle.len());
                    let (mut pending, mut copies) = (0, 0);
                    for m in oracle.range_mut(start..end) {
                        pending += usize::from(*m & PTB_PENDING != 0);
                        copies += usize::from(*m & PTB_COPY != 0);
                        *m &= !(PTB_PENDING | PTB_COPY);
                    }
                    assert_eq!(send.release_ptb(offset, count), (pending, copies));
                }
                11 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let end = (offset + count).min(oracle.len());
                    let start = offset.min(oracle.len());
                    let mut marked = 0;
                    for m in oracle.range_mut(start..end) {
                        marked += usize::from(*m & PTB_COPY == 0);
                        *m |= PTB_COPY;
                    }
                    assert_eq!(send.mark_ptb_copy(offset, count), marked);
                }
                12 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let end = (offset + count).min(oracle.len());
                    let start = offset.min(oracle.len());
                    let mut cleared = 0;
                    for m in oracle.range_mut(start..end) {
                        cleared += usize::from(*m & PTB_COPY != 0);
                        *m &= !PTB_COPY;
                    }
                    assert_eq!(send.clear_ptb_copy(offset, count), cleared);
                }
                _ => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let end = (offset + count).min(oracle.len());
                    let start = offset.min(oracle.len());
                    let mut cleared = 0;
                    for m in oracle.range_mut(start..end) {
                        cleared += usize::from(*m & PTB_PENDING != 0);
                        *m = (*m & !PTB_PENDING) | RETRANSMITTED;
                    }
                    assert_eq!(send.mark_retransmitted(offset, count), cleared);
                }
            }

            // Core invariants: marks match oracle, push_end/eor_end exact, singleton has no PTB bits.
            assert_eq!(send.len(), oracle.len());
            assert!(send.marks.iter().copied().eq(oracle.iter().copied()));
            let expected_push_end = oracle
                .iter()
                .rposition(|&m| m & 1 != 0)
                .map_or(0, |i| i + 1);
            let expected_eor_end = oracle
                .iter()
                .rposition(|&m| m & 2 != 0)
                .map_or(0, |i| i + 1);
            assert_eq!(send.push_end, expected_push_end);
            assert_eq!(send.eor_end, expected_eor_end);
            if let Some((pos, bits)) = send.marks.singleton() {
                assert_eq!(bits & !(1 | 2), 0, "singleton must not hold PTB bits");
                if bits & 1 != 0 {
                    saw_singleton_push = true;
                }
                if bits & 2 != 0 {
                    saw_singleton_eor = true;
                }
                if bits != 0 {
                    assert!(pos < oracle.len());
                    assert_eq!(oracle[pos], bits);
                }
            } else {
                saw_materialized = true;
            }

            // Query checks across random offset/count/end/size.
            let offset = next(oracle.len() + 3);
            let count = next(oracle.len() + 5);
            let available = oracle.len().saturating_sub(offset);
            let bounded = count.min(available);
            let tail: Vec<u8> = oracle.iter().skip(offset).take(bounded).copied().collect();

            let expected_record = tail
                .iter()
                .position(|&m| m & 2 != 0)
                .map_or(tail.len(), |n| n + 1);
            assert_eq!(send.record_len(offset, count), expected_record);
            assert_eq!(send.record_len_within(offset, bounded), expected_record);
            assert_eq!(
                send.tail_record_offset(offset, count),
                tail.iter()
                    .take(tail.len().saturating_sub(1))
                    .rposition(|&m| m & 2 != 0)
                    .map_or(offset, |n| offset + n + 1)
            );
            assert_eq!(send.pushed(offset, count), tail.iter().any(|&m| m & 1 != 0));
            assert_eq!(
                send.push_after(offset),
                oracle.iter().skip(offset).any(|&m| m & 1 != 0)
            );
            // If push_at_end returns true, PUSH must be ONLY on the last byte of [offset..offset+count)
            // and must also be the last PUSH in the buffer.
            if send.push_at_end(offset, count) {
                assert!(count != 0 && offset + count == expected_push_end);
                assert!(oracle[offset + count - 1] & 1 != 0);
                assert!(
                    oracle
                        .range(offset..offset + count - 1)
                        .all(|&m| m & 1 == 0)
                );
            }
            let size = 1 + next(16);
            let segments = next(12);
            let expected_seg = (0..segments).find(|&s| {
                let start = offset + s * size;
                let end = (start + size).min(oracle.len());
                start < end && oracle.range(start..end).any(|&m| m & 1 != 0)
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
                let start = (offset..hi).find(|&i| oracle[i] & flag != 0)?;
                let run = (start..hi)
                    .take(lim)
                    .take_while(|&i| oracle[i] & flag != 0)
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
                .filter(|&&m| m & PTB_PENDING != 0)
                .count();
            assert_eq!(send.count_ptb(offset, count), expected_count_ptb);
            assert_eq!(
                send.ptb_pending(offset),
                oracle.get(offset).is_some_and(|&m| m & PTB_PENDING != 0)
            );
            assert_eq!(
                send.ptb_copy(offset),
                oracle.get(offset).is_some_and(|&m| m & PTB_COPY != 0)
            );
            assert_eq!(
                send.retransmitted(offset),
                oracle.get(offset).is_some_and(|&m| m & RETRANSMITTED != 0)
            );

            // selected_slice agrees with contiguous on record-clipped count.
            assert_eq!(
                send.selected_slice(offset, expected_record),
                send.contiguous(offset, count)
            );
        }

        assert!(saw_singleton_push);
        assert!(saw_singleton_eor);
        assert!(saw_materialized);
        assert!(saw_full_ack_return_to_singleton);
        assert!(saw_ptb);
    }
}
