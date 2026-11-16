extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};

use crate::Payload;

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
    marks: VecDeque<u8>,
    capacity: usize,
    head: u64,
    shared: VecDeque<SharedSpan>,
    shared_output: Option<usize>,
    // Stream position of the last queued byte carrying PUSH, or u64::MAX for
    // none (no stream reaches that position), so that asking whether the
    // rest of the queue holds one needs no pass over it, as Linux keeps PSH
    // on the skb.
    last_push: u64,
    // The same for EOR: a selection past it needs no pass over its marks to
    // find its record's end, as Linux keeps EOR on the skb.
    last_eor: u64,
}

impl SendBuffer {
    // Rings reserved for `capacity` queued bytes at once.
    #[cfg(test)]
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut data = VecDeque::new();
        data.try_reserve_exact(capacity).map_err(|_| ())?;
        let mut marks = VecDeque::new();
        marks.try_reserve_exact(capacity).map_err(|_| ())?;
        Ok(Self {
            data,
            marks,
            capacity,
            head: 0,
            shared: VecDeque::new(),
            shared_output: None,
            last_push: u64::MAX,
            last_eor: u64::MAX,
        })
    }

    // A limit of `capacity` queued bytes with no ring yet: the rings are
    // allocated by `grow`, at the first write, as Linux allocates a
    // socket's skbs in sendmsg and none at socket creation.
    pub(crate) fn unallocated(capacity: usize) -> Self {
        Self {
            data: VecDeque::new(),
            marks: VecDeque::new(),
            capacity,
            head: 0,
            shared: VecDeque::new(),
            shared_output: None,
            last_push: u64::MAX,
            last_eor: u64::MAX,
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
        self.marks.try_reserve_exact(additional).map_err(|_| ())
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
        debug_assert!(self.push_offset().is_none() && self.eor_offset().is_none());
        self.data = VecDeque::new();
        self.marks = VecDeque::new();
        self.shared = VecDeque::new();
        self.last_push = u64::MAX;
        self.last_eor = u64::MAX;
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

    pub(crate) fn write(&mut self, input: &[u8]) -> usize {
        let count = input.len().min(self.remaining());
        self.assert_reserved(count);
        self.data.extend(&input[..count]);
        self.marks.resize(self.data.len(), 0);
        count
    }

    fn mark_slices(&self, offset: usize, count: usize) -> [&[u8]; 2] {
        let (front, back) = self.marks.as_slices();
        let [first, second] = ring_ranges(front.len(), self.marks.len(), offset, count);
        [&front[first], &back[second]]
    }

    fn mark_slices_mut(&mut self, offset: usize, count: usize) -> [&mut [u8]; 2] {
        let len = self.marks.len();
        let (front, back) = self.marks.as_mut_slices();
        let [first, second] = ring_ranges(front.len(), len, offset, count);
        [&mut front[first], &mut back[second]]
    }

    // Offset within the marks of up to `count` bytes from `offset` of the
    // first carrying `flag`. Each block is first tested whole, which needs
    // no early exit and so runs many marks per instruction.
    fn first_flagged(&self, flag: u8, offset: usize, count: usize) -> Option<usize> {
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
        if let Some(last) = self.marks.back_mut() {
            *last |= 1;
            self.last_push = self.head.wrapping_add(self.marks.len() as u64 - 1);
        }
    }

    // Offset of the last queued byte carrying PUSH.
    fn push_offset(&self) -> Option<usize> {
        Some(self.last_push)
            .filter(|&position| position != u64::MAX)
            .map(|position| position.wrapping_sub(self.head) as usize)
            .filter(|&offset| offset < self.marks.len())
    }

    // Records a PUSH mark at `offset`, where none is past the last one.
    fn note_push(&mut self, offset: usize) {
        if self.push_offset().is_none_or(|last| last < offset) {
            self.last_push = self.head.wrapping_add(offset as u64);
        }
    }

    // Finds the last PUSH mark again after marks at or past it went away.
    fn find_last_push(&mut self) {
        self.last_push = self
            .marks
            .iter()
            .rposition(|mark| mark & 1 != 0)
            .map_or(u64::MAX, |offset| self.head.wrapping_add(offset as u64));
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
        if last - offset < count {
            return true;
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
        let holding_last = (last - offset) / size;
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

    pub(crate) fn collapse_push(&mut self, offset: usize, count: usize) {
        for part in self.mark_slices_mut(offset, count) {
            for mark in part {
                *mark &= !1;
            }
        }
        let cleared = self
            .push_offset()
            .is_some_and(|last| last >= offset && last - offset < count);
        let end = offset + count - 1;
        if let Some(last) = self.marks.get_mut(end) {
            *last |= 1;
            self.note_push(end);
        } else if cleared {
            self.find_last_push();
        }
    }

    pub(crate) fn finish_send(&mut self, offset: usize, push: bool, end_of_record: bool) {
        if let Some(mark) = self.marks.get_mut(offset) {
            *mark |= u8::from(push) | (u8::from(end_of_record) << 1);
            if push {
                self.note_push(offset);
            }
            if end_of_record {
                self.note_end_of_record(offset);
            }
        }
    }

    pub(crate) fn mark_end_of_record(&mut self) {
        if let Some(last) = self.marks.back_mut() {
            *last |= 2;
            self.last_eor = self.head.wrapping_add(self.marks.len() as u64 - 1);
        }
    }

    // Offset of the last queued byte carrying EOR.
    fn eor_offset(&self) -> Option<usize> {
        Some(self.last_eor)
            .filter(|&position| position != u64::MAX)
            .map(|position| position.wrapping_sub(self.head) as usize)
            .filter(|&offset| offset < self.marks.len())
    }

    // Records an EOR mark at `offset`, where none is past the last one.
    // EOR marks are never cleared, so the last one moves only forward here
    // and back only when its byte goes.
    fn note_end_of_record(&mut self, offset: usize) {
        if self.eor_offset().is_none_or(|last| last < offset) {
            self.last_eor = self.head.wrapping_add(offset as u64);
        }
    }

    // Whether the last queued byte carries EOR: the queue's tail ends a
    // record, and nothing written later joins it.
    pub(crate) fn ends_record(&self) -> bool {
        self.len() != 0 && self.record_ends_after(self.len() - 1)
    }

    // Whether a byte at or past `offset` carries EOR.
    fn record_ends_after(&self, offset: usize) -> bool {
        self.eor_offset().is_some_and(|last| last >= offset)
    }

    // EOR is a local coalescing boundary, not a TCP wire flag or framing
    // guarantee (RFC 9293 section 3.7.1). PUSH may collapse; EOR never does.
    // Only a selection reaching the last EOR scans its marks.
    pub(crate) fn record_len(&self, offset: usize, limit: usize) -> usize {
        let limit = limit.min(self.len().saturating_sub(offset));
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
        self.marks
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
        let end = end.min(self.marks.len());
        let start = (offset..end).find(|&i| self.marks[i] & flag != 0)?;
        let len = self
            .marks
            .range(start..end)
            .take(limit)
            .take_while(|&byte| byte & flag != 0)
            .count();
        Some((start, len))
    }

    // Bytes of one range that carry PTB work.
    pub(crate) fn count_ptb(&self, offset: usize, count: usize) -> usize {
        self.marks
            .range(offset.min(self.marks.len())..)
            .take(count)
            .filter(|&byte| byte & PTB_PENDING != 0)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn ptb_pending(&self, offset: usize) -> bool {
        self.marks
            .get(offset)
            .is_some_and(|&byte| byte & PTB_PENDING != 0)
    }

    #[cfg(test)]
    pub(crate) fn ptb_copy(&self, offset: usize) -> bool {
        self.marks
            .get(offset)
            .is_some_and(|&byte| byte & PTB_COPY != 0)
    }

    #[cfg(test)]
    pub(crate) fn retransmitted(&self, offset: usize) -> bool {
        self.marks
            .get(offset)
            .is_some_and(|&byte| byte & RETRANSMITTED != 0)
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
        self.marks.truncate(len);
        // Discarding queued bytes is rare; only then is the queue searched
        // back to its new last mark.
        if self.last_push != u64::MAX && self.push_offset().is_none() {
            self.find_last_push();
        }
        if self.last_eor != u64::MAX && self.eor_offset().is_none() {
            self.last_eor = self
                .marks
                .iter()
                .rposition(|mark| mark & 2 != 0)
                .map_or(u64::MAX, |offset| self.head.wrapping_add(offset as u64));
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
        self.data.drain(..count);
        self.marks.drain(..count);
        self.head = self.head.wrapping_add(count as u64);
        if self.push_offset().is_none() {
            self.last_push = u64::MAX;
        }
        if self.eor_offset().is_none() {
            self.last_eor = u64::MAX;
        }
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
        self.marks.resize(self.data.len(), 0);
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
}
