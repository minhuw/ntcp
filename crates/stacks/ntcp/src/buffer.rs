extern crate alloc;

use alloc::{
    alloc::{Layout, alloc_zeroed},
    collections::VecDeque,
    vec::Vec,
};

use core::mem::MaybeUninit;

use crate::{Payload, seq::Seq};

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

#[derive(Debug)]
pub(crate) struct ReceiveOutcome {
    pub new_bytes: usize,
    pub sack_overflow: bool,
    // next() changed, including consumption of FIN.
    pub advanced: bool,
    // FIN became contiguous during this insertion, not merely accepted.
    pub fin: bool,
    // Nonempty segment starts away from the previous next(), even if rejected.
    pub out_of_order: bool,
}

// `len` zeroed elements, allocated as zeroed memory: their pages are not
// touched until used.
//
// SAFETY: the all-zero bit pattern must be a valid `T`.
unsafe fn zeroed_vec<T>(len: usize) -> Result<Vec<T>, ()> {
    let layout = Layout::array::<T>(len).map_err(|_| ())?;
    if layout.size() == 0 {
        return Ok(Vec::new());
    }
    let pointer = unsafe { alloc_zeroed(layout) };
    if pointer.is_null() {
        return Err(());
    }
    // Zeroed elements are valid (caller); the allocation uses Vec's exact layout.
    Ok(unsafe { Vec::from_raw_parts(pointer.cast(), len, len) })
}

// The presence bits of the 32 slots of one metadata word.
const PRESENT_BITS: u64 = 0x5555_5555_5555_5555;

// One bit per chunk of 32 receive slots (one metadata word), summarized
// upwards 64 bits per word, so that the next or previous chunk of interest
// is found in one step per level whatever the distance, as Linux finds the
// out-of-order queue's next skb in its rbtree rather than by walking the
// window. A chunk bit is stored as `interest ^ flip`: a summary of chunks
// holding a byte keeps flip 0, one of chunks missing a byte keeps it set,
// so that zeroed storage is the empty ring's state for both. A word's bit at
// the next level up is set exactly when the word has an interesting bit.
#[derive(Debug)]
struct ChunkSummary {
    // Level k occupies words[levels[k]..levels[k + 1]]; level 0 holds the
    // chunk bits and the last level a single word, kept in `top` rather
    // than allocated, so a ring of up to 64 chunks allocates nothing here.
    words: Vec<u64>,
    top: u64,
    levels: [usize; 8],
    depth: usize,
    flip: u64,
}

impl ChunkSummary {
    // The heap bytes `new(chunks, _)` allocates: every word but the top.
    fn allocation_bytes(chunks: usize) -> usize {
        let (mut len, mut total) = (chunks.div_ceil(64).max(1), 0);
        loop {
            total += len;
            if len == 1 {
                break;
            }
            len = len.div_ceil(64);
        }
        (total - 1) * core::mem::size_of::<u64>()
    }

    fn new(chunks: usize, flip: bool) -> Result<Self, ()> {
        let mut levels = [0; 8];
        let (mut depth, mut len, mut total) = (0, chunks.div_ceil(64).max(1), 0);
        loop {
            levels[depth] = total;
            total += len;
            depth += 1;
            if len == 1 {
                break;
            }
            len = len.div_ceil(64);
        }
        levels[depth] = total;
        Ok(Self {
            // SAFETY: zero is a valid u64.
            words: unsafe { zeroed_vec(total - 1)? },
            top: 0,
            levels,
            depth,
            flip: if flip { !0 } else { 0 },
        })
    }

    fn storage_bytes(&self) -> usize {
        self.words.capacity() * core::mem::size_of::<u64>()
    }

    fn clear(&mut self) {
        self.words.fill(0);
        self.top = 0;
    }

    // Word `at` of the levels as stored, the last one being `top`.
    fn raw(&self, at: usize) -> u64 {
        *self.words.get(at).unwrap_or(&self.top)
    }

    fn set_raw(&mut self, at: usize, value: u64) {
        *self.words.get_mut(at).unwrap_or(&mut self.top) = value;
    }

    // The interesting bits of word `word` of level `level`, or none past the
    // level's end (a summary bit of a word that does not exist).
    fn interest(&self, level: usize, word: usize) -> u64 {
        let at = self.levels[level] + word;
        if at < self.levels[level + 1] {
            self.raw(at) ^ self.flip
        } else {
            0
        }
    }

    fn mark(&mut self, chunk: usize, interesting: bool) {
        self.mark_level(0, chunk, interesting);
    }

    // `mark` for every chunk of `chunks`, a word at a time.
    fn mark_run(&mut self, chunks: core::ops::Range<usize>, interesting: bool) {
        let mut chunk = chunks.start;
        while chunk < chunks.end {
            let word = chunk / 64;
            let end = chunks.end.min((word + 1) * 64);
            let bits = (!0 >> (64 - (end - chunk))) << (chunk % 64);
            let at = self.levels[0] + word;
            let old = self.raw(at) ^ self.flip;
            let new = if interesting { old | bits } else { old & !bits };
            self.set_raw(at, new ^ self.flip);
            if (old != 0) != (new != 0) {
                self.mark_level(1, word, new != 0);
            }
            chunk = end;
        }
    }

    // Sets bit `index` of level `level` and the summary bits above it.
    fn mark_level(&mut self, level: usize, mut index: usize, mut interesting: bool) {
        for level in level..self.depth {
            let at = self.levels[level] + index / 64;
            let bit = 1 << (index % 64);
            let old = self.raw(at) ^ self.flip;
            let new = if interesting { old | bit } else { old & !bit };
            if new == old {
                return;
            }
            self.set_raw(at, new ^ self.flip);
            if (old != 0) == (new != 0) {
                return;
            }
            interesting = new != 0;
            index /= 64;
        }
    }

    // The first interesting chunk at or after `chunk`. A chunk past the end
    // of the ring may be returned; callers bound the result.
    fn next(&self, chunk: usize) -> Option<usize> {
        let (mut level, mut index) = (0, chunk);
        loop {
            let bits = self.interest(level, index / 64) & (!0 << (index % 64));
            if bits != 0 {
                index = index / 64 * 64 + bits.trailing_zeros() as usize;
                break;
            }
            if level + 1 == self.depth {
                return None;
            }
            level += 1;
            index = index / 64 + 1;
        }
        while level > 0 {
            level -= 1;
            let bits = self.interest(level, index);
            if bits == 0 {
                return None;
            }
            index = index * 64 + bits.trailing_zeros() as usize;
        }
        Some(index)
    }

    // The last interesting chunk at or before `chunk`, a chunk of the ring.
    fn previous(&self, chunk: usize) -> Option<usize> {
        let (mut level, mut index) = (0, chunk);
        loop {
            let bits = self.interest(level, index / 64) & (!0 >> (63 - index % 64));
            if bits != 0 {
                index = index / 64 * 64 + 63 - bits.leading_zeros() as usize;
                break;
            }
            if index < 64 || level + 1 == self.depth {
                return None;
            }
            level += 1;
            index = index / 64 - 1;
        }
        while level > 0 {
            level -= 1;
            index = index * 64 + 63 - self.interest(level, index).leading_zeros() as usize;
        }
        Some(index)
    }
}

#[derive(Debug)]
pub(crate) struct ReceiveBuffer {
    // A set presence bit implies the payload byte in that slot was initialized.
    // Every typed payload read checks presence first; clearing presence makes
    // the slot inaccessible until insertion writes a new byte before setting it.
    // Unset slots may contain uninitialized bytes; they are never read as u8.
    data: Vec<MaybeUninit<u8>>,
    pushed: bool,
    metadata: Vec<u8>,
    // Chunks of `metadata` holding a present slot, and chunks missing one.
    holding: ChunkSummary,
    missing: ChunkSummary,
    read_base: Seq,
    head: usize,
    contiguous_len: usize,
    // Initialized prefix in the existing ring, not yet admitted to receive state.
    deferred_syn: Option<(usize, bool, bool)>,
    fin_sequence: Option<Seq>,
    eof: bool,
    occupied: usize,
    latest: Option<Seq>,
    reported: [Option<Seq>; 4],
    // One first-new-byte anchor per arrival, independent of wire history.
    // Input never allocates reporting work; application-read anchors become
    // cumulative-only debt, bounded by capacity even if output is exhausted.
    report_pending: Vec<u8>,
    report_debt: usize,
    pending_first: Option<Seq>,
    dsack: Option<(Seq, Seq)>,
}

#[derive(Clone, Copy)]
pub(crate) struct ReceiveOutputUndo {
    reported: [Option<Seq>; 4],
    dsack: Option<(Seq, Seq)>,
    report_debt: usize,
    pending_first: Option<Seq>,
    pending_byte: Option<(usize, u8)>,
}

impl ReceiveBuffer {
    pub(crate) fn new(start: Seq, capacity: usize) -> Result<Self, ()> {
        if capacity == 0 || capacity >= 1usize << 31 {
            return Err(());
        }
        let mut data = Vec::new();
        data.try_reserve_exact(capacity).map_err(|_| ())?;
        // MaybeUninit elements need no initialization, and capacity was reserved.
        unsafe { data.set_len(capacity) };
        // Zeroed bytes clear every bit. SAFETY: zero is a valid u8.
        let metadata = unsafe { zeroed_vec(capacity.div_ceil(4))? };
        let report_pending = unsafe { zeroed_vec(capacity.div_ceil(8))? };
        let chunks = capacity.div_ceil(32);
        Ok(Self {
            data,
            pushed: false,
            metadata,
            holding: ChunkSummary::new(chunks, false)?,
            missing: ChunkSummary::new(chunks, true)?,
            read_base: start,
            head: 0,
            contiguous_len: 0,
            deferred_syn: None,
            fin_sequence: None,
            eof: false,
            occupied: 0,
            latest: None,
            reported: [None; 4],
            report_pending,
            report_debt: 0,
            pending_first: None,
            dsack: None,
        })
    }

    // Only the initial SYN prefix can be staged. No presence/reporting bits are
    // published until validated establishment; next() remains IRS+1 throughout.
    pub(crate) fn defer_syn(&mut self, payload: &[u8], fin: bool, push: bool) {
        assert!(!self.has_data() && self.fin_sequence.is_none() && self.deferred_syn.is_none());
        assert!(payload.len() <= self.capacity());
        assert!(!fin || payload.len() < self.capacity());
        for (offset, &byte) in payload.iter().enumerate() {
            let index = self.index(offset);
            self.data[index].write(byte);
        }
        self.deferred_syn = Some((payload.len(), fin, push));
    }

    pub(crate) fn promote_syn(&mut self) -> Option<usize> {
        let (count, fin, push) = self.deferred_syn.take()?;
        for offset in 0..count {
            let index = self.index(offset);
            self.set_present(index, true);
        }
        self.summarize_logical(0, count);
        self.occupied = count;
        self.contiguous_len = count;
        self.pushed = push && count != 0;
        if fin {
            self.fin_sequence = Some(self.next());
            self.eof = true;
        }
        Some(count)
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.data.capacity()
            + self.metadata.capacity()
            + self.report_pending.capacity()
            + self.holding.storage_bytes()
            + self.missing.storage_bytes()
    }

    // What `new(_, capacity)` allocates: storage_bytes of the ring it
    // returns, 1.375 bytes a slot (payload, 2-bit presence/PUSH, 1-bit
    // pending report) and the two chunk summaries, 1/128 byte a slot.
    pub(crate) fn allocation_bytes(capacity: usize) -> Option<usize> {
        capacity
            .checked_add(capacity.div_ceil(4))?
            .checked_add(capacity.div_ceil(8))?
            .checked_add(2 * ChunkSummary::allocation_bytes(capacity.div_ceil(32)))
    }

    pub(crate) fn capacity(&self) -> usize {
        self.data.len()
    }

    // Rebase the physical ring, not sequence/reporting state. Uninitialized slots
    // are copied only as MaybeUninit; payload reads still require presence.
    // The reference that `grow` is tested against.
    #[cfg(test)]
    pub(crate) fn grown(&self, capacity: usize) -> Result<Self, ()> {
        let mut result = Self::new(self.read_base, capacity)?;
        for offset in 0..self.data.len() {
            let index = self.index(offset);
            result.data[offset] = self.data[index];
            result.set_present(offset, self.is_present(index));
            result.set_push(offset, self.is_push(index));
            if self.report_pending[index / 8] & (1 << (index % 8)) != 0 {
                result.report_pending[offset / 8] |= 1 << (offset % 8);
            }
        }
        result.summarize(0..self.data.len());
        Ok(Self {
            data: result.data,
            metadata: result.metadata,
            holding: result.holding,
            missing: result.missing,
            report_pending: result.report_pending,
            head: 0,
            ..*self
        })
    }

    // Grows the ring in place to `capacity` slots, rounded up to a multiple
    // of 8 so that a slot keeps its position within a byte of either bitmap
    // and the bitmaps move as whole bytes. A capacity no larger than the
    // ring's changes nothing. The payload and both bitmaps are reserved
    // before anything changes; then, as VecDeque does, the shorter side of
    // the wrap moves: the wrapped prefix to just past the old end, or the
    // rest to the new end, moving `head`. Sequence and reporting state counts
    // from read_base and stays as it is; a ReceiveOutputUndo, which names a
    // bitmap byte, must not span a growth (reservations exclude reads). On
    // failure every slot and all state are as they were: a bitmap or payload
    // that grew before another failed keeps its storage, which storage_bytes
    // counts and the next growth reuses.
    pub(crate) fn grow(&mut self, capacity: usize) -> Result<(), ()> {
        let old = self.data.len();
        if capacity <= old {
            return Ok(());
        }
        let new = capacity.next_multiple_of(8);
        if new >= 1usize << 31 {
            return Err(());
        }
        let (metadata_len, pending_len) = (new / 4, new / 8);
        self.data.try_reserve_exact(new - old).map_err(|_| ())?;
        self.metadata
            .try_reserve_exact(metadata_len - self.metadata.len())
            .map_err(|_| ())?;
        self.report_pending
            .try_reserve_exact(pending_len - self.report_pending.len())
            .map_err(|_| ())?;
        // The summaries are rebuilt for the new chunks once the slots moved.
        let holding = ChunkSummary::new(new.div_ceil(32), false)?;
        let missing = ChunkSummary::new(new.div_ceil(32), true)?;
        // MaybeUninit elements need no initialization, and capacity was reserved.
        unsafe { self.data.set_len(new) };
        // Slots past the old end are empty: their bits in a shared last byte
        // were never set.
        self.metadata.resize(metadata_len, 0);
        self.report_pending.resize(pending_len, 0);
        self.holding = holding;
        self.missing = missing;
        let (head, added) = (self.head, new - old);
        if head == 0 {
            self.summarize(0..old);
            return Ok(());
        }
        let (from, to, count) = if head <= added && head <= old - head {
            (0, old, head)
        } else {
            self.head = head + added;
            (head, head + added, old - head)
        };
        // Unset slots are copied only as MaybeUninit, as in `grown`.
        self.data.copy_within(from..from + count, to);
        move_fields(&mut self.metadata, 2, from, to, count);
        move_fields(&mut self.report_pending, 1, from, to, count);
        // The slots of the old ring, wherever they are now.
        for range in self.ranges(0, old) {
            self.summarize(range);
        }
        Ok(())
    }

    pub(crate) fn clear(&mut self) {
        self.metadata.fill(0);
        self.holding.clear();
        self.missing.clear();
        self.pushed = false;
        self.read_base = Seq(0);
        self.head = 0;
        self.contiguous_len = 0;
        self.deferred_syn = None;
        self.fin_sequence = None;
        self.eof = false;
        self.occupied = 0;
        self.latest = None;
        self.reported = [None; 4];
        self.report_pending.fill(0);
        self.report_debt = 0;
        self.pending_first = None;
        self.dsack = None;
    }

    pub(crate) fn reset_start(&mut self, start: Seq) -> Result<(), ()> {
        if self.fin_sequence.is_some() || self.has_data() || self.deferred_syn.is_some() {
            return Err(());
        }
        self.read_base = start;
        self.dsack = None;
        Ok(())
    }

    // Reports the contiguous receive frontier; ACK scheduling and transmission belong to
    // the connection.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= reason=Gap filling advances cumulative frontier and removes consumed ordinary SACK ranges; test follows section-7 examples.
    //# When missing segments are received, the data receiver acknowledges the data
    //# normally by advancing the left window edge in the Acknowledgement Number
    //# Field of the TCP header. The SACK option does not change the meaning of the
    //# Acknowledgement Number field.
    pub(crate) fn next(&self) -> Seq {
        self.read_base
            .wrapping_add(self.contiguous_len as u32)
            .wrapping_add(u32::from(self.eof))
    }

    pub(crate) fn right_edge(&self) -> Seq {
        self.read_base.wrapping_add(self.data.len() as u32)
    }

    pub(crate) fn readable(&self) -> usize {
        self.contiguous_len
    }

    // The sequence after the last byte held beyond a gap, if any: the end
    // of Linux's out-of-order queue (ooo_last_skb). One summary walk from
    // the ring's end, however far that byte is from next().
    pub(crate) fn out_of_order_end(&self) -> Option<Seq> {
        if self.occupied == self.contiguous_len {
            return None;
        }
        let start = self.contiguous_len;
        let [first, second] = self.ranges(start, self.data.len() - start);
        let offset = match self.find_slot_back(second.clone(), true) {
            Some(index) => start + first.len() + index - second.start,
            None => start + self.find_slot_back(first.clone(), true)? - first.start,
        };
        Some(self.read_base.wrapping_add(offset as u32 + 1))
    }

    pub(crate) fn has_data(&self) -> bool {
        self.occupied != 0 || self.deferred_syn.is_some_and(|(count, _, _)| count != 0)
    }

    pub(crate) fn take_push(&mut self) -> bool {
        core::mem::take(&mut self.pushed)
    }

    pub(crate) fn eof(&self) -> bool {
        self.eof
    }

    // Call once on the raw packet, before trimming or inserting; insertion must not
    // replace this record with one based on the trimmed payload. FIN is not data.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-2
    //= reason=Existing SACK negotiation gates duplicate reports, no separate D-SACK capability flag or handshake option.
    //# The use of D-SACK does not require separate negotiation between a TCP
    //# sender and receiver that have already negotiated SACK capability.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
    //# (1) A D-SACK block is only used to report a duplicate contiguous
    //# sequence of data received by the receiver in the most recent packet.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Records raw duplicate start/exclusive end before trimming, including already-read cumulative bytes and wrap.
    //# (3) The left edge of the D-SACK block specifies the first sequence
    //# number of the duplicate contiguous sequence, and the right edge of
    //# the D-SACK block specifies the sequence number immediately following
    //# the last sequence in the duplicate contiguous sequence.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4.2
    //= reason=First raw prefix/earliest retained-range overlap wins; erratum365 fixes illustrative second arrival to 2500-2999 and existing example6 test matches it.
    //# When the SACK option is used for reporting partial duplicate
    //# segments, the first D-SACK block reports the first duplicate sub-
    //# segment.  If the data packet being acknowledged contains multiple
    //# partial duplicate sub-segments, then only the first such duplicate
    //# sub-segment is reported in the SACK option.
    pub(crate) fn record_duplicate(&mut self, sequence: Seq, payload_len: usize) {
        self.dsack = None;
        if payload_len == 0 || payload_len >= 1usize << 31 {
            return;
        }
        let frontier = self.read_base.wrapping_add(self.contiguous_len as u32);
        let distance = sequence.distance_from(frontier);
        if distance == 1 << 31 {
            return;
        }
        let start = distance as i32 as i64;
        let end = start + payload_len as i64;
        if start < 0 {
            self.dsack = Some((
                sequence,
                sequence.wrapping_add(payload_len.min((-start) as usize) as u32),
            ));
            return;
        }
        let left = self.find_presence(self.contiguous_len + start as usize, true);
        let right = self
            .find_presence(left, false)
            .min(self.contiguous_len + end as usize);
        if left < right {
            self.dsack = Some((
                self.read_base.wrapping_add(left as u32),
                self.read_base.wrapping_add(right as u32),
            ));
        }
    }

    pub(crate) fn clear_dsack(&mut self) {
        self.dsack = None;
    }

    // Whether the next SACK-bearing output reports a duplicate.
    pub(crate) fn dsack_pending(&self) -> bool {
        self.dsack.is_some()
    }

    // Whether sack_blocks reports any block: a pending duplicate, or a byte
    // retained beyond the contiguous prefix (occupied counts every present
    // slot, and the prefix is all present), as Linux tests its out-of-order
    // queue for emptiness.
    pub(crate) fn has_sack_blocks(&self) -> bool {
        self.dsack.is_some() || self.occupied > self.contiguous_len
    }

    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Ordinary SACK selects newest contiguous retained union first, except arrivals advancing the cumulative frontier. RFC 2883 DSACK is a separate first-block extension, not asserted as ordinary RFC 2018 behavior.
    //# * The first SACK block (i.e., the one immediately following the kind and
    //# length fields in the option) MUST specify the contiguous block of data
    //# containing the segment which triggered this ACK, unless that segment
    //# advanced the Acknowledgment Number field in the header.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Four successful first-block anchors provide report history; anchors resolve through the presence bitmap after merges and cumulative advancement. Encoding failure does not change history.
    //# * The SACK option SHOULD be filled out by repeating the most recently
    //# reported SACK blocks (based on first SACK blocks in previous SACK options)
    //# that are not subsets of a SACK block already included in the SACK option
    //# being constructed.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= reason=Ordinary emitted ranges represent queued contiguous non-frontier data, not holes or FIN; focused examples assert full edges and coalescing.
    //# This option contains a list of some of the blocks of contiguous sequence
    //# space occupied by data that has been received and queued within the window.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= reason=Receive ranges begin at first retained byte, as asserted by RFC example edges.
    //# This is the first sequence number of this block.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= reason=Ranges use exclusive right edges; example tests assert last+1 and merges.
    //# This is the sequence number immediately following the last sequence number
    //# of this block.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= reason=Ordinary ranges coalesce adjacent retained bytes and exclude contiguous frontier. DSACK extension is not an ordinary isolated block.
    //# Each block represents received bytes of data that are contiguous and
    //# isolated; that is, the bytes just below the block, (Left Edge of Block - 1),
    //# and just above the block, (Right Edge of Block), have not been received.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-2
    //= reason=D-SACK alters option contents only; cumulative ACK still follows receive frontier and ACK scheduling remains normal TCP.
    //# This document does not make any changes to TCP's use of the
    //# cumulative acknowledgement field, or to the TCP receiver's decision
    //# of *when* to send an acknowledgement packet.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
    //# (4) If the D-SACK block reports a duplicate contiguous sequence from
    //# a (possibly larger) block of data in the receiver's data queue above
    //# the cumulative acknowledgement, then the second SACK block in that
    //# SACK option should specify that (possibly larger) block of data.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
    //# (5) Following the SACK blocks described above for reporting duplicate
    //# segments, additional SACK blocks can be used for reporting additional
    //# blocks of data, as specified in RFC 2018.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Pending raw duplicate occupies first block, ahead of containing/other ordinary SACK ranges; option budget may decline duplicate report, not mislabel an ordinary block as DSACK.
    //# When D-SACK is used, the
    //# first block of the SACK option should be a D-SACK block specifying
    //# the sequence numbers for the duplicate segment that triggers the
    //# acknowledgement.
    pub(crate) fn sack_blocks(&self, max_blocks: usize) -> [Option<(u32, u32)>; 4] {
        let mut blocks = [None; 4];
        let limit = max_blocks.min(blocks.len());
        if limit == 0 {
            return blocks;
        }
        let mut count = 0;
        fn add(
            blocks: &mut [Option<(u32, u32)>; 4],
            count: &mut usize,
            limit: usize,
            range: Option<(Seq, Seq)>,
        ) {
            if let Some((left, right)) = range {
                let block = Some((left.0, right.0));
                if *count < limit && !blocks[..*count].contains(&block) {
                    blocks[*count] = block;
                    *count += 1;
                }
            }
        }
        if let Some(duplicate) = self.dsack {
            let containing = self.block_at(duplicate.0);
            if containing.is_none() || limit > 1 {
                add(&mut blocks, &mut count, limit, Some(duplicate));
            }
            if let Some((left, right)) = containing {
                blocks[count] = Some((left.0, right.0));
                count += 1;
            }
        }
        add(
            &mut blocks,
            &mut count,
            limit,
            self.report_anchor().and_then(|seq| self.block_at(seq)),
        );
        for &seq in &self.reported {
            add(
                &mut blocks,
                &mut count,
                limit,
                seq.and_then(|seq| self.block_at(seq)),
            );
        }
        // Fill unused wire slots with actual retained blocks, not arrival history.
        let mut offset = self.contiguous_len;
        while count < limit {
            let left = self.find_presence(offset, true);
            if left == self.data.len() {
                break;
            }
            let right = self.find_presence(left, false);
            let range = (
                self.read_base.wrapping_add(left as u32),
                self.read_base.wrapping_add(right as u32),
            );
            let block = Some((range.0.0, range.1.0));
            if !blocks[..count].contains(&block) {
                blocks[count] = block;
                count += 1;
            }
            offset = right;
        }
        blocks
    }

    pub(crate) fn output_undo(&self) -> ReceiveOutputUndo {
        let pending_byte = self
            .report_anchor()
            .filter(|&seq| self.pending(seq))
            .map(|seq| {
                let index = self.index(seq.distance_from(self.read_base) as usize) / 8;
                (index, self.report_pending[index])
            });
        ReceiveOutputUndo {
            reported: self.reported,
            dsack: self.dsack,
            report_debt: self.report_debt,
            pending_first: self.pending_first,
            pending_byte,
        }
    }

    // Output consumes at most one pending anchor. Reservation ownership excludes
    // input/read mutation, so restoring that byte and fixed report metadata is exact.
    pub(crate) fn restore_output(&mut self, undo: ReceiveOutputUndo) {
        self.reported = undo.reported;
        self.dsack = undo.dsack;
        self.report_debt = undo.report_debt;
        self.pending_first = undo.pending_first;
        if let Some((index, value)) = undo.pending_byte {
            self.report_pending[index] = value;
        }
    }

    // Called only after a SACK-bearing packet has been successfully encoded.
    pub(crate) fn commit_sack(&mut self, first: (u32, u32)) {
        let mut history = [None; 4];
        let mut count = 0;
        // A bridge can merge several historical anchors into one block. Resolve
        // and deduplicate before truncation so distinct recent blocks survive.
        for anchor in core::iter::once(Some(Seq(first.0)))
            .chain(self.reported)
            .flatten()
        {
            if let Some((left, _)) = self.block_at(anchor)
                && count < history.len()
                && !history[..count].contains(&Some(left))
            {
                history[count] = Some(left);
                count += 1;
            }
        }
        self.reported = history;
        self.dsack = None;
    }

    pub(crate) fn has_pending_report(&self) -> bool {
        self.report_debt != 0
    }

    fn pending(&self, seq: Seq) -> bool {
        let offset = seq.distance_from(self.read_base) as usize;
        offset < self.data.len() && {
            let index = self.index(offset);
            self.report_pending[index / 8] & (1 << (index % 8)) != 0
        }
    }

    fn report_anchor(&self) -> Option<Seq> {
        if let Some(latest) = self.latest
            && self.pending(latest)
        {
            return Some(latest);
        }
        self.pending_first.or(self.latest)
    }

    pub(crate) fn commit_report(&mut self) {
        self.report_debt = self.report_debt.saturating_sub(1);
        if let Some(anchor) = self.report_anchor()
            && self.pending(anchor)
        {
            let offset = anchor.distance_from(self.read_base) as usize;
            let index = self.index(offset);
            self.report_pending[index / 8] &= !(1 << (index % 8));
            if self.pending_first == Some(anchor) {
                self.pending_first = self.find_pending(offset + 1);
            }
        }
    }

    fn find_pending(&self, mut offset: usize) -> Option<Seq> {
        if self.occupied == 0 || self.report_debt == 0 {
            return None;
        }
        while offset < self.data.len() {
            let index = self.index(offset);
            if index.is_multiple_of(8)
                && index + 8 <= self.data.len()
                && offset + 8 <= self.data.len()
            {
                let bits = self.report_pending[index / 8];
                if bits == 0 {
                    offset += 8;
                    continue;
                }
                return Some(
                    self.read_base
                        .wrapping_add((offset + bits.trailing_zeros() as usize) as u32),
                );
            }
            if self.report_pending[index / 8] & (1 << (index % 8)) != 0 {
                return Some(self.read_base.wrapping_add(offset as u32));
            }
            offset += 1;
        }
        None
    }

    fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)> {
        let offset = seq.distance_from(self.read_base) as usize;
        if offset < self.contiguous_len
            || offset >= self.data.len()
            || !self.is_present(self.index(offset))
        {
            return None;
        }
        // The block reaches back to just past the last missing slot, or to the
        // contiguous prefix; both edges are found through the chunk summaries.
        let mut left = self.contiguous_len;
        let mut end = offset;
        for range in self.ranges(left, offset - left).into_iter().rev() {
            end -= range.len();
            if let Some(index) = self.find_slot_back(range.clone(), false) {
                left = end + index - range.start + 1;
                break;
            }
        }
        let right = self.find_presence(offset, false);
        Some((
            self.read_base.wrapping_add(left as u32),
            self.read_base.wrapping_add(right as u32),
        ))
    }

    // The first offset from `offset` whose slot's presence is `present`, or
    // the capacity. The chunk summaries skip every chunk without such a slot,
    // so the cost does not grow with the distance.
    fn find_presence(&self, offset: usize, present: bool) -> usize {
        let capacity = self.data.len();
        // The contiguous prefix accounts for every retained byte on the common
        // in-order path.
        if present && self.occupied == self.contiguous_len {
            return if offset < self.contiguous_len {
                offset
            } else {
                capacity
            };
        }
        if offset >= capacity {
            return capacity;
        }
        let mut at = offset;
        for range in self.ranges(offset, capacity - offset) {
            if let Some(index) = self.find_slot(range.clone(), present) {
                return at + index - range.start;
            }
            at += range.len();
        }
        capacity
    }

    // The presence bits of chunk `chunk` (its metadata word, PUSH bits
    // masked), and the presence bits of its slots within the ring.
    fn chunk_presence(&self, chunk: usize) -> (u64, u64) {
        let byte = chunk * 8;
        let word = match self.metadata.get(byte..byte + 8) {
            Some(bytes) => u64::from_le_bytes(bytes.try_into().unwrap()),
            None => {
                let mut raw = [0; 8];
                let tail = &self.metadata[byte..];
                raw[..tail.len()].copy_from_slice(tail);
                u64::from_le_bytes(raw)
            }
        };
        let slots = (self.data.len() - chunk * 32).min(32);
        let valid = PRESENT_BITS >> (64 - 2 * slots);
        (word & valid, valid)
    }

    // The presence bits of chunk `chunk` whose presence is `present`.
    fn chunk_matching(&self, chunk: usize, present: bool) -> u64 {
        let (word, valid) = self.chunk_presence(chunk);
        if present { word } else { valid & !word }
    }

    fn summary(&self, present: bool) -> &ChunkSummary {
        if present {
            &self.holding
        } else {
            &self.missing
        }
    }

    // The first slot of physical `range` whose presence is `present`.
    fn find_slot(&self, range: core::ops::Range<usize>, present: bool) -> Option<usize> {
        if range.is_empty() {
            return None;
        }
        let mut chunk = range.start / 32;
        let mut bits = self.chunk_matching(chunk, present) & (!0 << (2 * (range.start % 32)));
        while bits == 0 {
            chunk = self.summary(present).next(chunk + 1)?;
            if chunk * 32 >= range.end {
                return None;
            }
            bits = self.chunk_matching(chunk, present);
        }
        let index = chunk * 32 + bits.trailing_zeros() as usize / 2;
        (index < range.end).then_some(index)
    }

    // The last slot of physical `range` whose presence is `present`.
    fn find_slot_back(&self, range: core::ops::Range<usize>, present: bool) -> Option<usize> {
        if range.is_empty() {
            return None;
        }
        let last = range.end - 1;
        let mut chunk = last / 32;
        let mut bits = self.chunk_matching(chunk, present) & (!0 >> (63 - 2 * (last % 32)));
        while bits == 0 {
            if chunk == 0 {
                return None;
            }
            chunk = self.summary(present).previous(chunk - 1)?;
            if (chunk + 1) * 32 <= range.start {
                return None;
            }
            bits = self.chunk_matching(chunk, present);
        }
        let index = chunk * 32 + (63 - bits.leading_zeros() as usize) / 2;
        (index >= range.start).then_some(index)
    }

    // Brings the chunk summaries up to date with the presence bits of the
    // chunks of physical `range`.
    fn summarize(&mut self, range: core::ops::Range<usize>) {
        if range.is_empty() {
            return;
        }
        for chunk in range.start / 32..=(range.end - 1) / 32 {
            let (word, valid) = self.chunk_presence(chunk);
            self.holding.mark(chunk, word != 0);
            self.missing.mark(chunk, word != valid);
        }
    }

    // `summarize` for physical `range` after every slot of it became present
    // or absent: only its two end chunks can hold slots outside it.
    fn summarize_filled(&mut self, range: core::ops::Range<usize>, present: bool) {
        if range.is_empty() {
            return;
        }
        let (first, last) = (range.start / 32, (range.end - 1) / 32);
        self.summarize(range.start..range.start + 1);
        if last > first + 1 {
            self.holding.mark_run(first + 1..last, present);
            self.missing.mark_run(first + 1..last, !present);
        }
        self.summarize(range.end - 1..range.end);
    }

    // `summarize` for the slots of `len` bytes from `offset`.
    fn summarize_logical(&mut self, offset: usize, len: usize) {
        for range in self.ranges(offset, len) {
            self.summarize(range);
        }
    }

    fn index(&self, offset: usize) -> usize {
        (self.head + offset) % self.data.len()
    }

    // Each slot uses a presence bit followed by a PUSH bit, four slots per byte.
    fn is_present(&self, index: usize) -> bool {
        self.metadata[index / 4] & (1 << (2 * (index % 4))) != 0
    }

    fn set_present(&mut self, index: usize, present: bool) {
        let shift = 2 * (index % 4);
        // Both insertion and removal clear stale PUSH marks on reused slots.
        self.metadata[index / 4] =
            (self.metadata[index / 4] & !(3 << shift)) | (u8::from(present) << shift);
    }

    fn is_push(&self, index: usize) -> bool {
        self.metadata[index / 4] & (2 << (2 * (index % 4))) != 0
    }

    fn set_push(&mut self, index: usize, push: bool) {
        let mask = 2 << (2 * (index % 4));
        if push {
            self.metadata[index / 4] |= mask;
        } else {
            self.metadata[index / 4] &= !mask;
        }
    }

    // The slots of `len` bytes from `offset`, as at most two index ranges
    // (the second one after the ring wraps).
    fn ranges(&self, offset: usize, len: usize) -> [core::ops::Range<usize>; 2] {
        let start = self.index(offset);
        let first = len.min(self.data.len() - start);
        [start..start + first, 0..len - first]
    }

    // `set_present` for every slot of `range`, four slots per metadata byte.
    fn set_present_range(&mut self, range: core::ops::Range<usize>, present: bool) {
        let mut index = range.start;
        while index < range.end && !index.is_multiple_of(4) {
            self.set_present(index, present);
            index += 1;
        }
        let whole = (range.end - index) / 4 * 4;
        self.metadata[index / 4..(index + whole) / 4].fill(if present { 0x55 } else { 0 });
        index += whole;
        for index in index..range.end {
            self.set_present(index, present);
        }
    }

    // Clears the PUSH marks of every slot of `range`; whether there was one.
    fn take_push_range(&mut self, range: core::ops::Range<usize>) -> bool {
        let mut any = false;
        let mut index = range.start;
        while index < range.end && !index.is_multiple_of(4) {
            any |= self.is_push(index);
            self.set_push(index, false);
            index += 1;
        }
        let whole = (range.end - index) / 4 * 4;
        for metadata in &mut self.metadata[index / 4..(index + whole) / 4] {
            any |= *metadata & 0xaa != 0;
            *metadata &= 0x55;
        }
        index += whole;
        for index in index..range.end {
            any |= self.is_push(index);
            self.set_push(index, false);
        }
        any
    }

    // Whether every slot of `range` holds a byte.
    fn all_present(&self, range: core::ops::Range<usize>) -> bool {
        let mut index = range.start;
        while index < range.end && !index.is_multiple_of(4) {
            if !self.is_present(index) {
                return false;
            }
            index += 1;
        }
        // Folded without an early exit, so many metadata bytes are tested
        // per instruction.
        let whole = (range.end - index) / 4 * 4;
        let all = self.metadata[index / 4..(index + whole) / 4]
            .iter()
            .fold(0x55, |all, metadata| all & metadata);
        if all & 0x55 != 0x55 {
            return false;
        }
        index += whole;
        (index..range.end).all(|index| self.is_present(index))
    }

    // Clears the reporting anchors of every slot of `range`.
    fn clear_pending_range(&mut self, range: core::ops::Range<usize>) {
        let mut index = range.start;
        while index < range.end && !index.is_multiple_of(8) {
            self.report_pending[index / 8] &= !(1 << (index % 8));
            index += 1;
        }
        let whole = (range.end - index) / 8 * 8;
        self.report_pending[index / 8..(index + whole) / 8].fill(0);
        index += whole;
        for index in index..range.end {
            self.report_pending[index / 8] &= !(1 << (index % 8));
        }
    }

    pub(crate) fn peek(&self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.contiguous_len);
        for (offset, dst) in out[..count].iter_mut().enumerate() {
            let index = self.index(offset);
            assert!(self.is_present(index));
            // Presence guarantees an initialized payload byte.
            *dst = unsafe { self.data[index].assume_init() };
        }
        count
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.contiguous_len);
        let mut copied = 0;
        for range in self.ranges(0, count) {
            assert!(self.all_present(range.clone()));
            let len = range.len();
            // SAFETY: presence guarantees initialized payload bytes; `out`
            // holds `count` bytes and the ranges cover `count` slots.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.data[range.clone()].as_ptr().cast::<u8>(),
                    out[copied..].as_mut_ptr(),
                    len,
                );
            }
            copied += len;
            self.set_present_range(range.clone(), false);
            self.summarize_filled(range.clone(), false);
            self.clear_pending_range(range);
        }
        self.occupied -= count;
        self.head = self.index(count);
        self.read_base = self.read_base.wrapping_add(count as u32);
        self.contiguous_len -= count;
        if self
            .pending_first
            .is_some_and(|seq| seq.distance_from(self.read_base) as usize >= self.data.len())
        {
            self.pending_first = self.find_pending(0);
        }
        count
    }

    // Retains in-capacity text and pending FIN; the connection performs state and segment
    // acceptability checks.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //# Segments with higher beginning sequence numbers SHOULD be held for later processing
    //# (SHLD-31).
    #[cfg(test)]
    pub(crate) fn insert(&mut self, sequence: Seq, payload: &[u8], fin: bool) -> ReceiveOutcome {
        self.insert_with_push(sequence, payload, fin, false)
    }

    pub(crate) fn insert_with_push(
        &mut self,
        sequence: Seq,
        payload: &[u8],
        fin: bool,
        push: bool,
    ) -> ReceiveOutcome {
        self.insert_observed(sequence, payload, fin, push, |_, _| {})
    }

    // Accepted runs are relative to the unread payload base, excluding duplicates and FIN.
    pub(crate) fn insert_observed(
        &mut self,
        sequence: Seq,
        payload: &[u8],
        fin: bool,
        push: bool,
        mut accepted: impl FnMut(usize, usize),
    ) -> ReceiveOutcome {
        let previous_next = self.next();
        let had_holes = self.occupied > self.contiguous_len;
        let mut outcome = ReceiveOutcome {
            new_bytes: 0,
            sack_overflow: false,
            advanced: false,
            fin: false,
            out_of_order: (!payload.is_empty() || fin) && sequence != previous_next,
        };
        if self.eof || (payload.is_empty() && !fin) {
            return outcome;
        }

        let capacity = self.data.len();
        let data_limit = self
            .fin_sequence
            .map_or(capacity, |end| end.distance_from(self.read_base) as usize);
        // In-order text that fits, with no byte retained beyond the contiguous
        // prefix: every byte is new and extends the prefix, so the per-byte
        // path below reduces to copying the run and marking it present, with
        // no reporting anchor and PUSH taken at once. A FIN on it follows
        // every retained byte, so it is kept when it lies within capacity
        // and none is kept yet, as below.
        let start = self.contiguous_len;
        if !payload.is_empty()
            && !outcome.out_of_order
            && !had_holes
            && start + payload.len() <= data_limit
        {
            let mut copied = 0;
            for range in self.ranges(start, payload.len()) {
                let len = range.len();
                // SAFETY: the ranges cover `payload.len()` slots of the ring.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        payload[copied..].as_ptr(),
                        self.data[range.clone()].as_mut_ptr().cast::<u8>(),
                        len,
                    );
                }
                copied += len;
                self.set_present_range(range.clone(), true);
                self.summarize_filled(range, true);
            }
            let end = start + payload.len();
            accepted(start, end);
            outcome.new_bytes = payload.len();
            self.occupied += payload.len();
            self.contiguous_len = end;
            self.pushed |= push;
            if fin && self.fin_sequence.is_none() && end < capacity {
                self.fin_sequence = Some(self.read_base.wrapping_add(end as u32));
            }
            if self.fin_sequence == Some(self.next()) {
                self.eof = true;
                outcome.fin = true;
            }
            outcome.advanced = true;
            self.latest = None;
            return outcome;
        }
        let mut new_anchor = None;
        let mut run = None;
        // Offsets of the first and past the last byte that became present.
        let mut stored: Option<(usize, usize)> = None;
        for (offset, &byte) in payload.iter().enumerate() {
            let position = sequence.wrapping_add(offset as u32);
            let distance = position.distance_from(self.read_base) as usize;
            if distance >= data_limit {
                if let Some((start, end)) = run.take() {
                    accepted(start, end);
                }
                continue;
            }
            let index = self.index(distance);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
            //# If a segment's contents straddle the boundary between old and new, only the
            //# new parts are processed.
            if !self.is_present(index) {
                self.data[index].write(byte);
                self.set_present(index, true);
                outcome.new_bytes += 1;
                self.occupied += 1;
                new_anchor.get_or_insert(position);
                let entry = run.get_or_insert((distance, distance));
                entry.1 = distance + 1;
                let entry = stored.get_or_insert((distance, distance));
                entry.0 = entry.0.min(distance);
                entry.1 = entry.1.max(distance + 1);
            } else if let Some((start, end)) = run.take() {
                accepted(start, end);
            }
        }
        if let Some((start, end)) = run {
            accepted(start, end);
        }
        if let Some((start, end)) = stored {
            self.summarize_logical(start, end - start);
        }

        if let Some(anchor) = new_anchor
            && (outcome.out_of_order || had_holes)
        {
            let offset = anchor.distance_from(self.read_base) as usize;
            let index = self.index(offset);
            self.report_pending[index / 8] |= 1 << (index % 8);
            if self
                .pending_first
                .is_none_or(|old| offset < old.distance_from(self.read_base) as usize)
            {
                self.pending_first = Some(anchor);
            }
            // ponytail: after application reads, cumulative-only ACK debt is
            // coalesced at capacity under prolonged output exhaustion. Retained
            // fragments keep individual anchors; use driver backpressure if
            // every already-consumed arrival must retain a separate ACK.
            self.report_debt = self.report_debt.saturating_add(1).min(capacity);
        }
        if push && !payload.is_empty() {
            let last = sequence.wrapping_add(payload.len() as u32 - 1);
            let distance = last.distance_from(self.read_base) as usize;
            // A duplicate may introduce PSH on buffered out-of-order text, but
            // never re-notify a mark already passed by the contiguous frontier.
            if distance >= self.contiguous_len && distance < data_limit {
                let index = self.index(distance);
                if self.is_present(index) {
                    self.set_push(index, true);
                }
            }
        }

        if fin && self.fin_sequence.is_none() {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
            //# while the FIN is considered to occur after the last actual data octet in a
            //# segment in which it occurs.
            let end = sequence.wrapping_add(payload.len() as u32);
            let distance = end.distance_from(self.read_base) as usize;
            // Reject a FIN before retained text. Packed presence lookup skips
            // empty capacity and uses the contiguous-prefix fast path.
            if distance < capacity && self.find_presence(distance, true) == capacity {
                self.fin_sequence = Some(end);
            }
        }
        // The prefix extends over the retained bytes up to the next missing
        // slot, taking their PUSH marks.
        let end = self.find_presence(self.contiguous_len, false);
        for range in self.ranges(self.contiguous_len, end - self.contiguous_len) {
            self.pushed |= self.take_push_range(range);
        }
        self.contiguous_len = end;
        // This buffer consumes FIN once after preceding data; SYN processing is in the
        // connection.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //# one and only one copy of the control will be acted upon
        if self.fin_sequence == Some(self.next()) {
            self.eof = true;
            outcome.fin = true;
        }
        outcome.advanced = self.next() != previous_next;
        self.latest = None;
        if !outcome.advanced && !payload.is_empty() {
            let offset = sequence.distance_from(self.read_base) as usize;
            let left = self.find_presence(offset.max(self.contiguous_len), true);
            if left < data_limit && left < offset.saturating_add(payload.len()) {
                self.latest = new_anchor.or(Some(self.read_base.wrapping_add(left as u32)));
            }
        }
        outcome
    }
}

// The `width`-bit field of `slot` in a bitmap of 8 / `width` slots per byte.
fn field(map: &[u8], width: usize, slot: usize) -> u8 {
    let per_byte = 8 / width;
    (map[slot / per_byte] >> (width * (slot % per_byte))) & ((1 << width) - 1)
}

fn set_field(map: &mut [u8], width: usize, slot: usize, value: u8) {
    let per_byte = 8 / width;
    let shift = width * (slot % per_byte);
    let byte = &mut map[slot / per_byte];
    *byte = (*byte & !(((1 << width) - 1) << shift)) | (value << shift);
}

// Moves the fields of slots [from, from + count) up to [to, to + count),
// to > from, overlapping as memmove may, then clears the source slots left
// behind. A distance of whole bytes moves the inner bytes as bytes.
fn move_fields(map: &mut [u8], width: usize, from: usize, to: usize, count: usize) {
    let per_byte = 8 / width;
    let distance = to - from;
    let end = from + count;
    // Highest slot first, so no source is overwritten before it moves.
    let mut slot = end;
    if distance.is_multiple_of(per_byte) {
        while slot > from && !slot.is_multiple_of(per_byte) {
            slot -= 1;
            set_field(map, width, slot + distance, field(map, width, slot));
        }
        let first = from.next_multiple_of(per_byte);
        if slot > first {
            map.copy_within(
                first / per_byte..slot / per_byte,
                (first + distance) / per_byte,
            );
            slot = first;
        }
    }
    while slot > from {
        slot -= 1;
        set_field(map, width, slot + distance, field(map, width, slot));
    }
    let cleared = from..end.min(to);
    let mut slot = cleared.start;
    while slot < cleared.end && !slot.is_multiple_of(per_byte) {
        set_field(map, width, slot, 0);
        slot += 1;
    }
    let whole = cleared.end.saturating_sub(slot) / per_byte * per_byte;
    map[slot / per_byte..(slot + whole) / per_byte].fill(0);
    for slot in slot + whole..cleared.end {
        set_field(map, width, slot, 0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn resizing_wrapped_ring_preserves_holes_push_fin_and_reporting() {
        let start = Seq(u32::MAX - 5);
        let mut recv = ReceiveBuffer::new(start, 9).unwrap();
        recv.insert_with_push(start, b"abc", false, true);
        let mut out = [0; 3];
        assert_eq!(recv.read(&mut out), 3); // physical head no longer zero
        let base = recv.read_base;
        recv.insert_with_push(base.wrapping_add(2), b"fghi", true, true);
        recv.record_duplicate(base.wrapping_add(2), 2);
        let before = (
            recv.next(),
            recv.fin_sequence,
            recv.latest,
            recv.reported,
            recv.report_debt,
            recv.pending_first,
            recv.dsack,
            recv.pushed,
        );
        let mut grown = recv.grown(17).unwrap();
        assert_eq!(
            (
                grown.next(),
                grown.fin_sequence,
                grown.latest,
                grown.reported,
                grown.report_debt,
                grown.pending_first,
                grown.dsack,
                grown.pushed
            ),
            before
        );
        for offset in 0..9 {
            let seq = base.wrapping_add(offset as u32);
            assert_eq!(grown.pending(seq), recv.pending(seq));
            assert_eq!(
                grown.is_present(grown.index(offset)),
                recv.is_present(recv.index(offset))
            );
            assert_eq!(
                grown.is_push(grown.index(offset)),
                recv.is_push(recv.index(offset))
            );
        }
        grown.insert(base, b"de", false);
        assert!(grown.eof());
        let mut out = [0; 16];
        assert_eq!(grown.read(&mut out), 6);
        assert_eq!(&out[..6], b"defghi");
        assert!(grown.take_push());
        assert_eq!(grown.next(), base.wrapping_add(7));
    }

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
    fn merged_report_history_preserves_distinct_recent_blocks() {
        for start in [Seq(0), Seq(u32::MAX - 63)] {
            for limit in [3, 4] {
                let mut recv = ReceiveBuffer::new(start, 128).unwrap();
                for offset in [10, 30, 50, 70, 90] {
                    recv.insert(start.wrapping_add(offset), b"x", false);
                    let first = recv.sack_blocks(limit)[0].unwrap();
                    recv.commit_sack(first);
                    recv.commit_report();
                }
                recv.insert(start.wrapping_add(49), &[1; 42], false);
                let bridge = recv.sack_blocks(limit);
                let history = recv.reported;
                assert_eq!(recv.sack_blocks(limit), bridge);
                assert_eq!(recv.reported, history); // Failed encoding has no commit.
                recv.commit_sack(bridge[0].unwrap());
                recv.commit_report();
                recv.insert(start.wrapping_add(110), b"x", false);
                let block =
                    |left, right| Some((start.wrapping_add(left).0, start.wrapping_add(right).0));
                let report = recv.sack_blocks(limit);
                assert_eq!(
                    &report[..3],
                    &[block(110, 111), block(49, 91), block(30, 31)]
                );
                assert_eq!(report[3], if limit == 4 { block(10, 11) } else { None });
            }
        }
    }

    #[test]
    fn empty_and_contiguous_presence_search_preserves_fin_and_wrap() {
        let capacity = 8 * 1024 * 1024;
        let start = Seq(u32::MAX - 1);
        let mut recv = ReceiveBuffer::new(start, capacity).unwrap();
        assert_eq!(recv.find_presence(0, true), capacity);
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        recv.insert(start, b"abc", false);
        assert_eq!(recv.find_presence(2, true), 2);
        assert_eq!(recv.find_presence(3, true), capacity);
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        assert!(recv.insert(start.wrapping_add(3), &[], true).fin);
        let mut out = [0; 3];
        assert_eq!(recv.read(&mut out), 3);
        assert_eq!(out, *b"abc");
        assert_eq!(recv.find_pending(0), None);

        let mut recv = ReceiveBuffer::new(start, 64).unwrap();
        recv.insert(start.wrapping_add(40), b"x", false);
        assert!(!recv.insert(start.wrapping_add(3), &[], true).fin);
        assert_eq!(recv.fin_sequence, None);
        assert_eq!(recv.find_presence(3, true), 40);
    }

    fn receive_packet(recv: &mut ReceiveBuffer, sequence: Seq, payload: &[u8]) -> ReceiveOutcome {
        if let Some(first) = recv.sack_blocks(4)[0] {
            recv.commit_sack(first);
        }
        recv.commit_report();
        recv.record_duplicate(sequence, payload.len());
        let behind = recv.next().distance_from(sequence);
        let skip = if behind < 1 << 31 {
            (behind as usize).min(payload.len())
        } else {
            0
        };
        recv.insert(sequence.wrapping_add(skip as u32), &payload[skip..], false)
    }

    fn occupied_data(recv: &ReceiveBuffer) -> Vec<Option<(u8, bool)>> {
        (0..recv.data.len())
            .map(|index| {
                recv.is_present(index).then(|| {
                    // Only occupied slots have initialized bytes; never inspect holes.
                    (
                        unsafe { recv.data[index].assume_init() },
                        recv.is_push(index),
                    )
                })
            })
            .collect()
    }

    fn assert_ranges(recv: &ReceiveBuffer) {
        let mut expected = Vec::new();
        let mut offset = recv.contiguous_len;
        while offset < recv.data.len() {
            if !recv.is_present(recv.index(offset)) {
                offset += 1;
                continue;
            }
            let start = offset;
            while offset < recv.data.len() && recv.is_present(recv.index(offset)) {
                offset += 1;
            }
            expected.push((
                recv.read_base.wrapping_add(start as u32),
                recv.read_base.wrapping_add(offset as u32),
            ));
        }
        for &(left, right) in &expected {
            assert_eq!(recv.block_at(left), Some((left, right)));
            assert_eq!(
                recv.block_at(right.wrapping_add(u32::MAX)),
                Some((left, right))
            );
        }
        assert_eq!(recv.occupied, occupied_data(recv).iter().flatten().count());
        assert_eq!(recv.has_sack_blocks(), recv.sack_blocks(1)[0].is_some());
        assert_summaries(recv);
    }

    // The chunk summaries agree with the presence bits at every level, and
    // the searches built on them with a pass over the slots.
    fn assert_summaries(recv: &ReceiveBuffer) {
        let chunks = recv.capacity().div_ceil(32);
        for (summary, missing) in [(&recv.holding, false), (&recv.missing, true)] {
            for chunk in 0..chunks {
                let (word, valid) = recv.chunk_presence(chunk);
                let interesting = if missing { word != valid } else { word != 0 };
                let bit = summary.interest(0, chunk / 64) >> (chunk % 64) & 1;
                assert_eq!(bit == 1, interesting, "{missing} {chunk}");
            }
            for level in 1..summary.depth {
                for word in 0..summary.levels[level] - summary.levels[level - 1] {
                    let bit = summary.interest(level, word / 64) >> (word % 64) & 1;
                    assert_eq!(bit == 1, summary.interest(level - 1, word) != 0);
                }
            }
        }
        // The first present and the first missing slot from each offset.
        let capacity = recv.capacity();
        let mut first = alloc::vec![[capacity; 2]; capacity + 1];
        for offset in (0..capacity).rev() {
            first[offset] = first[offset + 1];
            first[offset][usize::from(recv.is_present(recv.index(offset)))] = offset;
        }
        let mut offset = recv.contiguous_len;
        while offset < capacity {
            assert_eq!(
                recv.find_presence(offset, false),
                first[offset][0],
                "{offset}"
            );
            assert_eq!(
                recv.find_presence(offset, true),
                first[offset][1],
                "{offset}"
            );
            offset += 1 + offset % 97;
        }
    }

    #[test]
    fn receive_storage_stays_within_three_bytes_per_slot() {
        // allocation_bytes is what a ring of each capacity holds, chunk
        // summaries included, and stays within 3 bytes a slot.
        for capacity in (1..300).chain([2047, 2048, 2049, 65_536, 1 << 20, 3 << 20]) {
            let recv = ReceiveBuffer::new(Seq(0), capacity).unwrap();
            assert!(recv.storage_bytes() <= 3 * capacity, "{capacity}");
            assert_eq!(
                Some(recv.storage_bytes()),
                ReceiveBuffer::allocation_bytes(capacity),
                "{capacity}"
            );
        }
        let recv = ReceiveBuffer::new(Seq(0), 2048).unwrap();
        assert_eq!(
            recv.holding.storage_bytes() + recv.missing.storage_bytes(),
            0
        );
    }

    #[test]
    fn chunk_summaries_match_a_bitset_over_four_levels() {
        let mut state = 0x2f6b_95a1_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        // 300,000 chunks: 4,688 words, then 74, 2 and 1.
        let chunks = 300_000;
        for flip in [false, true] {
            let mut summary = ChunkSummary::new(chunks, flip).unwrap();
            assert_eq!(summary.depth, 4);
            let mut model = alloc::vec![flip; chunks];
            for _ in 0..3000 {
                // Runs, so that whole words and levels empty and fill.
                let (at, len, set) = (next(chunks), 1 + next(5000), next(2) == 0);
                let run = at..(at + len).min(chunks);
                if next(2) == 0 {
                    summary.mark_run(run.clone(), set);
                } else {
                    run.clone().for_each(|chunk| summary.mark(chunk, set));
                }
                model[run].fill(set);
                let chunk = next(chunks);
                let after = (chunk..chunks).find(|&c| model[c]);
                assert_eq!(summary.next(chunk).filter(|&c| c < chunks), after);
                let before = (0..=chunk).rev().find(|&c| model[c]);
                assert_eq!(summary.previous(chunk), before);
            }
        }
    }

    #[test]
    fn chunk_summaries_find_blocks_across_levels_wrap_and_growth() {
        let mut state = 0x6c07_8965_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        // 140,000 slots, 4,375 chunks, summarized in three levels.
        let start = Seq(u32::MAX - 70_000);
        let mut recv = ReceiveBuffer::new(start, 140_000).unwrap();
        assert_eq!(recv.holding.depth, 3);
        let (mut wrapped, mut grown) = (0, 0);
        for step in 0..300 {
            match next(10) {
                0..=5 => {
                    // A third fill the hole at the frontier.
                    let frontier = next(3) == 0;
                    let offset = recv.contiguous_len + next(if frontier { 1 } else { 140_000 });
                    let long = next(4) == 0;
                    let len = 1 + next(if long { 40_000 } else { 3000 });
                    let sequence = recv.read_base.wrapping_add(offset as u32);
                    recv.insert(sequence, &alloc::vec![step as u8; len], false);
                }
                6..=8 => {
                    let mut out = alloc::vec![0; next(recv.capacity() + 1)];
                    recv.read(&mut out);
                }
                _ if recv.capacity() < 300_000 => {
                    let capacity = recv.capacity() + 1 + next(60_000);
                    recv.grow(capacity).unwrap();
                    grown += 1;
                }
                _ => {}
            }
            wrapped += usize::from(recv.head != 0 && recv.occupied > recv.contiguous_len);
            assert_ranges(&recv);
        }
        assert!(wrapped > 20 && grown >= 4, "{wrapped} {grown}");
    }

    #[test]
    fn clear_reuses_storage_without_exposing_old_payload_push_fin_or_sack() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 3), 17).unwrap();
        let storage = (recv.data.as_ptr(), recv.metadata.as_ptr());
        for complete in [false, true] {
            let start = recv.next();
            recv.insert_with_push(start, b"ab", false, true);
            recv.read(&mut [0; 1]); // Move the ring head; leave unread text.
            recv.insert_with_push(start.wrapping_add(5), b"old", true, true);
            recv.record_duplicate(start.wrapping_add(5), 3);
            if complete {
                recv.insert(start.wrapping_add(2), b"cde", false);
                assert!(recv.eof());
            }
            assert!(recv.has_data());
            recv.clear();
            assert_eq!((recv.data.as_ptr(), recv.metadata.as_ptr()), storage);
            assert!(recv.metadata.iter().all(|&byte| byte == 0));
            assert!(occupied_data(&recv).iter().all(Option::is_none));
            assert!(!recv.has_data() && !recv.eof() && !recv.take_push());
            assert_eq!(recv.head, 0);
            assert_eq!(recv.fin_sequence, None);
            assert_eq!(recv.sack_blocks(4), [None; 4]);
            recv.reset_start(Seq(100)).unwrap();
            let mut out = [0xaa; 17];
            assert_eq!(recv.read(&mut out), 0);
            assert_eq!(recv.insert(Seq(100), b"new", false).new_bytes, 3);
            assert!(!recv.take_push());
            assert_eq!(recv.read(&mut out), 3);
            assert_eq!(&out[..3], b"new");
            assert_eq!(&out[3..], &[0xaa; 14]);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Ordinary SACK selects newest contiguous retained union first, except arrivals advancing the cumulative frontier. RFC 2883 DSACK is a separate first-block extension, not asserted as ordinary RFC 2018 behavior.
    //# * The first SACK block (i.e., the one immediately following the kind and
    //# length fields in the option) MUST specify the contiguous block of data
    //# containing the segment which triggered this ACK, unless that segment
    //# advanced the Acknowledgment Number field in the header.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= type=test
    //= reason=Four successful first-block anchors provide report history; anchors resolve through the presence bitmap after merges and cumulative advancement. Encoding failure does not change history.
    //# * The SACK option SHOULD be filled out by repeating the most recently
    //# reported SACK blocks (based on first SACK blocks in previous SACK options)
    //# that are not subsets of a SACK block already included in the SACK option
    //# being constructed.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Gap filling advances cumulative frontier and removes consumed ordinary SACK ranges; test follows section-7 examples.
    //# When missing segments are received, the data receiver acknowledges the data
    //# normally by advancing the left window edge in the Acknowledgement Number
    //# Field of the TCP header. The SACK option does not change the meaning of the
    //# Acknowledgement Number field.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Ordinary emitted ranges represent queued contiguous non-frontier data, not holes or FIN; focused examples assert full edges and coalescing.
    //# This option contains a list of some of the blocks of contiguous sequence
    //# space occupied by data that has been received and queued within the window.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Receive ranges begin at first retained byte, as asserted by RFC example edges.
    //# This is the first sequence number of this block.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Ranges use exclusive right edges; example tests assert last+1 and merges.
    //# This is the sequence number immediately following the last sequence number
    //# of this block.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Ordinary ranges coalesce adjacent retained bytes and exclude contiguous frontier. DSACK extension is not an ordinary isolated block.
    //# Each block represents received bytes of data that are contiguous and
    //# isolated; that is, the bytes just below the block, (Left Edge of Block - 1),
    //# and just above the block, (Right Edge of Block), have not been received.
    fn sack_rfc2018_examples_repeat_recent_blocks_and_merge() {
        // RFC 2018 section 7 cases 2 and 3; ordinary SACK, without DSACK.
        let mut recv = ReceiveBuffer::new(Seq(5000), 4000).unwrap();
        for sequence in (5500..9000).step_by(500) {
            recv.insert(Seq(sequence), &[1; 500], false);
            assert_eq!(recv.next(), Seq(5000));
            assert_eq!(
                recv.sack_blocks(3),
                [Some((5500, sequence + 500)), None, None, None]
            );
            assert_ranges(&recv);
        }
        recv.insert(Seq(5000), &[2; 500], false);
        assert_eq!(recv.next(), Seq(9000));
        assert_eq!(recv.sack_blocks(4), [None; 4]);

        let mut recv = ReceiveBuffer::new(Seq(5000), 4000).unwrap();
        recv.insert(Seq(5000), &[1; 500], false);
        let expected = [
            [Some((6000, 6500)), None, None, None],
            [Some((7000, 7500)), Some((6000, 6500)), None, None],
            [
                Some((8000, 8500)),
                Some((7000, 7500)),
                Some((6000, 6500)),
                None,
            ],
        ];
        for (sequence, blocks) in [6000, 7000, 8000].into_iter().zip(expected) {
            recv.insert(Seq(sequence), &[1; 500], false);
            assert_eq!(recv.next(), Seq(5500));
            assert_eq!(recv.sack_blocks(3), blocks);
            assert_eq!(recv.sack_blocks(1), [blocks[0], None, None, None]);
            assert_ranges(&recv);
            recv.commit_sack(blocks[0].unwrap());
            recv.commit_report();
        }
        recv.insert(Seq(6500), &[2; 500], false);
        assert_eq!(
            recv.sack_blocks(3),
            [Some((6000, 7500)), Some((8000, 8500)), None, None]
        );
        recv.insert(Seq(5500), &[2; 500], false);
        assert_eq!(recv.next(), Seq(7500));
        assert_eq!(recv.sack_blocks(3), [Some((8000, 8500)), None, None, None]);
        assert_ranges(&recv);
    }

    #[test]
    fn sack_full_ranges_reorder_merge_read_and_wrap() {
        for start in [Seq(0), Seq(u32::MAX - 9), Seq(u32::MAX - 65540)] {
            let mut recv = ReceiveBuffer::new(start, 70000).unwrap();
            for offset in [65536, 10, 30, 20, 40] {
                receive_packet(&mut recv, start.wrapping_add(offset), b"ab");
                assert_ranges(&recv);
            }
            let block =
                |left, right| Some((start.wrapping_add(left).0, start.wrapping_add(right).0));
            assert_eq!(recv.sack_blocks(0), [None; 4]);
            assert_eq!(
                recv.sack_blocks(3),
                [block(40, 42), block(20, 22), block(30, 32), None]
            );
            assert_eq!(
                recv.sack_blocks(99),
                [block(40, 42), block(20, 22), block(30, 32), block(10, 12)]
            );
            receive_packet(&mut recv, start.wrapping_add(12), &[b'x'; 18]);
            assert_eq!(
                recv.sack_blocks(4),
                [
                    block(20, 22),
                    block(10, 32),
                    block(40, 42),
                    block(65536, 65538)
                ]
            );
            recv.clear_dsack();
            assert_eq!(
                recv.sack_blocks(4),
                [block(10, 32), block(40, 42), block(65536, 65538), None]
            );
            receive_packet(&mut recv, start, &[b'y'; 10]);
            assert_eq!(recv.next(), start.wrapping_add(32));
            assert_eq!(
                recv.sack_blocks(4),
                [block(40, 42), block(65536, 65538), None, None]
            );
            assert_eq!(recv.read(&mut [0; 32]), 32);
            assert_ranges(&recv);
            receive_packet(&mut recv, start.wrapping_add(32), &[b'z'; 8]);
            assert_eq!(recv.sack_blocks(4), [block(65536, 65538), None, None, None]);
            assert_ranges(&recv);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
    //# (1) A D-SACK block is only used to report a duplicate contiguous
    //# sequence of data received by the receiver in the most recent packet.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Records raw duplicate start/exclusive end before trimming, including already-read cumulative bytes and wrap.
    //# (3) The left edge of the D-SACK block specifies the first sequence
    //# number of the duplicate contiguous sequence, and the right edge of
    //# the D-SACK block specifies the sequence number immediately following
    //# the last sequence in the duplicate contiguous sequence.
    fn dsack_raw_prefix_after_read_latest_packet_and_commit() {
        for start in [Seq(100), Seq(u32::MAX - 3)] {
            let mut recv = ReceiveBuffer::new(start, 16).unwrap();
            receive_packet(&mut recv, start, b"abcdefgh");
            assert_eq!(recv.read(&mut [0; 8]), 8);
            receive_packet(&mut recv, start, b"XXXXXXXX");
            let old = Some((start.0, start.wrapping_add(8).0));
            assert_eq!(recv.sack_blocks(4), [old, None, None, None]);
            assert_eq!(recv.sack_blocks(4), [old, None, None, None]); // Failed send does not commit.
            recv.clear_dsack();
            assert_eq!(recv.sack_blocks(4), [None; 4]);
            let mixed = receive_packet(&mut recv, start.wrapping_add(6), b"XXij");
            assert_eq!(mixed.new_bytes, 2);
            assert_eq!(
                recv.sack_blocks(4),
                [
                    Some((start.wrapping_add(6).0, start.wrapping_add(8).0)),
                    None,
                    None,
                    None
                ]
            );
            let mut out = [0; 2];
            assert_eq!(recv.read(&mut out), 2);
            assert_eq!(&out, b"ij");
            receive_packet(&mut recv, start.wrapping_add(1), b"XX");
            assert_eq!(
                recv.sack_blocks(1)[0],
                Some((start.wrapping_add(1).0, start.wrapping_add(3).0))
            );
            receive_packet(&mut recv, start.wrapping_add(10), b"k");
            assert_eq!(recv.sack_blocks(4), [None; 4]);
            recv.insert(start.wrapping_add(11), b"", true);
            recv.record_duplicate(start.wrapping_add(11), 1); // Received FIN is not data.
            assert_eq!(recv.sack_blocks(4), [None; 4]);
            recv.record_duplicate(start.wrapping_add(10), 2);
            assert_eq!(
                recv.sack_blocks(4)[0],
                Some((start.wrapping_add(10).0, start.wrapping_add(11).0))
            );
            recv.record_duplicate(start, 0);
            assert_eq!(recv.sack_blocks(4), [None; 4]);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
    //# (4) If the D-SACK block reports a duplicate contiguous sequence from
    //# a (possibly larger) block of data in the receiver's data queue above
    //# the cumulative acknowledgement, then the second SACK block in that
    //# SACK option should specify that (possibly larger) block of data.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
    //# (5) Following the SACK blocks described above for reporting duplicate
    //# segments, additional SACK blocks can be used for reporting additional
    //# blocks of data, as specified in RFC 2018.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4.2
    //= type=test
    //= reason=First raw prefix/earliest retained-range overlap wins; erratum365 fixes illustrative second arrival to 2500-2999 and existing example6 test matches it.
    //# When the SACK option is used for reporting partial duplicate
    //# segments, the first D-SACK block reports the first duplicate sub-
    //# segment.  If the data packet being acknowledged contains multiple
    //# partial duplicate sub-segments, then only the first such duplicate
    //# sub-segment is reported in the SACK option.
    fn dsack_first_duplicate_region_and_containing_full_range() {
        let mut recv = ReceiveBuffer::new(Seq(1000), 4000).unwrap();
        receive_packet(&mut recv, Seq(3500), &[b'a'; 500]);
        receive_packet(&mut recv, Seq(1500), &[b'b'; 500]);
        // RFC2883 example 6, erratum 365: second delayed block is 2500-2999.
        receive_packet(&mut recv, Seq(2500), &[b'c'; 500]);
        receive_packet(&mut recv, Seq(1500), &[b'x'; 1500]);
        assert_eq!(
            recv.sack_blocks(3),
            [
                Some((1500, 2000)),
                Some((1500, 3000)),
                Some((3500, 4000)),
                None
            ]
        );
        assert_ranges(&recv);
        recv.clear_dsack();
        assert_eq!(
            recv.sack_blocks(4),
            [Some((1500, 3000)), Some((3500, 4000)), None, None]
        );
        receive_packet(&mut recv, Seq(1800), &[b'x'; 100]);
        assert_eq!(
            recv.sack_blocks(4),
            [
                Some((1800, 1900)),
                Some((1500, 3000)),
                Some((3500, 4000)),
                None
            ]
        );
        receive_packet(&mut recv, Seq(1000), &[b'y'; 600]);
        assert_eq!(
            recv.sack_blocks(4),
            [Some((1500, 1600)), Some((3500, 4000)), None, None]
        );
        assert_ranges(&recv);
        // An old prefix wins over a later, separate OOO duplicate region.
        receive_packet(&mut recv, Seq(2800), &[b'z'; 800]);
        assert_eq!(recv.sack_blocks(4)[0], Some((2800, 3000)));
    }

    #[test]
    fn one_block_budget_preserves_full_range_and_below_ack_dsack() {
        for start in [Seq(1000), Seq(u32::MAX - 12)] {
            let mut recv = ReceiveBuffer::new(start, 64).unwrap();
            receive_packet(&mut recv, start.wrapping_add(10), &[b'x'; 10]);
            receive_packet(&mut recv, start.wrapping_add(12), &[b'x'; 3]);
            let containing = Some((start.wrapping_add(10).0, start.wrapping_add(20).0));
            let duplicate = Some((start.wrapping_add(12).0, start.wrapping_add(15).0));
            assert_eq!(recv.sack_blocks(0), [None; 4]);
            assert_eq!(recv.sack_blocks(1), [containing, None, None, None]);
            // Planning a smaller option did not consume the pending duplicate.
            assert_eq!(recv.sack_blocks(2), [duplicate, containing, None, None]);
            receive_packet(&mut recv, start, &[b'y'; 10]);
            recv.record_duplicate(start.wrapping_add(12), 3);
            assert_eq!(recv.sack_blocks(1), [duplicate, None, None, None]);
            recv.clear_dsack();
            assert_eq!(recv.sack_blocks(1), [None; 4]);
        }
    }

    #[test]
    fn exhausted_output_bounds_report_work_without_losing_readable_bytes() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 7), 17).unwrap();
        let storage = (
            recv.data.as_ptr(),
            recv.metadata.as_ptr(),
            recv.report_pending.as_ptr(),
        );
        for _ in 0..8 {
            let start = recv.next();
            for offset in (1..17).step_by(2) {
                assert_eq!(
                    recv.insert(start.wrapping_add(offset), b"a", false)
                        .new_bytes,
                    1
                );
            }
            recv.insert(start, &[b'b'; 17], false);
            let mut out = [0; 17];
            assert_eq!(recv.read(&mut out), 17);
            assert!(
                out.iter()
                    .enumerate()
                    .all(|(i, &byte)| byte == if i % 2 == 0 { b'b' } else { b'a' })
            );
            assert_eq!(recv.reported, [None; 4]); // Arrival is not report history.
            assert!(recv.report_debt <= 17);
            assert_eq!(recv.sack_blocks(4), [None; 4]); // Read data is never fabricated as queued SACK.
        }
        assert_eq!(recv.report_debt, 17);
        for _ in 0..17 {
            recv.commit_report();
        }
        assert!(!recv.has_pending_report());
        assert_eq!(
            (
                recv.data.as_ptr(),
                recv.metadata.as_ptr(),
                recv.report_pending.as_ptr()
            ),
            storage
        );
    }

    // In-order arrivals beyond no retained byte take the copying path, the
    // rest the per-byte one. Mixed at random across ring wraps, with partial
    // reads, they count every new byte once and deliver the stream exactly.
    #[test]
    fn copying_and_per_byte_insertion_deliver_the_same_stream() {
        for capacity in [61, 64, 256] {
            let start = Seq(u32::MAX - 40);
            let mut recv = ReceiveBuffer::new(start, capacity).unwrap();
            let stream: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
            let mut received = alloc::vec![false; stream.len()];
            let mut random = 7u32;
            let mut draw = |bound: u32| {
                random = random.wrapping_mul(1664525).wrapping_add(1013904223);
                ((random >> 8) % bound) as usize
            };
            let mut delivered = Vec::new();
            let mut out = alloc::vec![0; capacity];
            while delivered.len() < stream.len() {
                let base = delivered.len();
                let frontier = base + recv.readable();
                let (from, len) = if draw(3) == 0 {
                    (frontier + 1 + draw(12), 1 + draw(8))
                } else {
                    (frontier, 1 + draw(24))
                };
                let end = (from + len).min(base + capacity).min(stream.len());
                if from < end {
                    let fresh = (from..end).filter(|&i| !received[i]).count();
                    let outcome = recv.insert_with_push(
                        start.wrapping_add(from as u32),
                        &stream[from..end],
                        false,
                        draw(2) == 0,
                    );
                    assert_eq!(outcome.new_bytes, fresh, "{from}..{end}");
                    received[from..end].fill(true);
                }
                let want = draw(capacity as u32 + 1);
                let count = recv.read(&mut out[..want]);
                delivered.extend_from_slice(&out[..count]);
            }
            assert_eq!(delivered, stream);
            assert_eq!(recv.readable(), 0);
        }
    }

    #[test]
    fn alternating_window_retains_every_byte_across_wrap_and_bridges() {
        for capacity in [255, 256, 8192] {
            let start = Seq(u32::MAX - 64);
            let mut recv = ReceiveBuffer::new(start, capacity).unwrap();
            for offset in (1..capacity).step_by(2) {
                let outcome =
                    recv.insert_with_push(start.wrapping_add(offset as u32), b"a", false, true);
                assert_eq!(outcome.new_bytes, 1);
                assert!(!outcome.sack_overflow);
                assert_eq!(
                    recv.sack_blocks(4)[0],
                    Some((
                        start.wrapping_add(offset as u32).0,
                        start.wrapping_add(offset as u32 + 1).0
                    ))
                );
            }
            assert_ranges(&recv);
            for offset in (0..capacity).step_by(2) {
                assert_eq!(
                    recv.insert(start.wrapping_add(offset as u32), b"b", false)
                        .new_bytes,
                    1
                );
            }
            assert_eq!(recv.readable(), capacity);
            assert!(recv.take_push());
            assert_eq!(recv.sack_blocks(4), [None; 4]);
            let mut out = alloc::vec![0; capacity];
            assert_eq!(recv.read(&mut out), capacity);
            assert!(
                out.iter()
                    .enumerate()
                    .all(|(i, b)| *b == if i % 2 == 0 { b'b' } else { b'a' })
            );
            assert!(!recv.has_data());
            // Reuse at a non-word-aligned ring head.
            let next = recv.next();
            recv.insert(next, b"abc", false);
            recv.read(&mut out[..3]);
            let next = recv.next();
            recv.insert(next.wrapping_add(33), b"xyz", true);
            recv.insert(next, &[b'q'; 33], false);
            assert!(recv.eof());
            assert_eq!(recv.read(&mut out), 36);
        }
    }

    #[test]
    fn bounded_recency_survives_many_arrivals_and_metadata_matches_ring() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 10), 256).unwrap();
        let mut random = 1u32;
        for _ in 0..4000 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let offset = random % 260;
            let sequence = recv.next().wrapping_add(offset);
            receive_packet(&mut recv, sequence, &[b'x'; 3]);
            assert_ranges(&recv);
            if random & 7 == 0 {
                let next = recv.next();
                receive_packet(&mut recv, next, b"abc");
                recv.read(&mut [0; 16]);
                assert_ranges(&recv);
            }
        }
    }
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
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# If a segment's contents straddle the boundary between old and new, only the new
    //# parts are processed.
    fn wraps_trims_overlaps_and_reuses_read_credit() {
        let start = Seq(u32::MAX - 2);
        let mut recv = ReceiveBuffer::new(start, 6).unwrap();
        let result = recv.insert(start.wrapping_add(2), b"cdefgh", false);
        assert_eq!(result.new_bytes, 4);
        assert!(result.out_of_order);
        assert!(!result.advanced);
        // Out-of-order bytes are retained but unreadable until the gap is filled.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //= type=test
        //# Segments with higher beginning sequence numbers SHOULD be held for later
        //# processing (SHLD-31).
        assert_eq!(recv.readable(), 0);
        assert_eq!(
            (0..recv.data.len()).filter(|&i| recv.is_present(i)).count(),
            4
        );
        let result = recv.insert(start.wrapping_add(u32::MAX), b"!abXYZ", false);
        assert_eq!(result.new_bytes, 2);
        assert!(result.advanced);
        assert_eq!(recv.next(), Seq(3));
        assert_eq!(recv.right_edge(), Seq(3));
        assert_eq!(recv.insert(start, b"XXXXXX", false).new_bytes, 0);
        assert_eq!(recv.insert(recv.right_edge(), b"g", false).new_bytes, 0);
        let mut out = [0; 8];
        assert_eq!(recv.read(&mut out[..2]), 2);
        assert_eq!(&out[..2], b"ab");
        assert_eq!(recv.next(), Seq(3));
        assert_eq!(recv.right_edge(), Seq(5));
        assert_eq!(recv.insert(Seq(3), b"ghi", false).new_bytes, 2);
        assert_eq!(recv.read(&mut out), 6);
        assert_eq!(&out[..6], b"cdefgh");
        assert_eq!(recv.read(&mut out), 0);
        assert_eq!(recv.next(), Seq(5));
        assert_eq!(
            (0..recv.data.len()).filter(|&i| recv.is_present(i)).count(),
            0
        );
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# while the FIN is considered to occur after the last actual data octet in a segment
    //# in which it occurs.
    fn pending_fin_waits_for_gap_and_only_consumes_once() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 1), 8).unwrap();
        let pending = recv.insert(Seq(0), b"cd", true);
        assert_eq!(pending.new_bytes, 2);
        assert!(pending.out_of_order);
        assert!(!pending.fin);
        assert!(!pending.advanced);
        assert_eq!(recv.fin_sequence, Some(Seq(2)));
        assert!(!recv.insert(Seq(2), b"", true).fin);
        assert_eq!(recv.insert(Seq(2), b"ignored", false).new_bytes, 0);
        let completed = recv.insert(Seq(u32::MAX - 1), b"abXXtail", false);
        assert_eq!(completed.new_bytes, 2);
        assert!(completed.advanced && completed.fin);
        assert!(!completed.out_of_order);
        assert_eq!(recv.next(), Seq(3));
        assert!(recv.eof());
        let duplicate = recv.insert(Seq(2), b"", true);
        assert!(duplicate.out_of_order);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //= type=test
        //# one and only one copy of the control will be acted upon
        assert!(!duplicate.fin && !duplicate.advanced);
        assert_eq!(recv.insert(Seq(3), b"x", true).new_bytes, 0);
        let mut out = [0; 8];
        assert_eq!(recv.read(&mut out[..1]), 1);
        assert_eq!(out[0], b'a');
        assert_eq!(recv.next(), Seq(3));
        assert_eq!(recv.read(&mut out), 3);
        assert_eq!(&out[..3], b"bcd");
        assert_eq!(recv.next(), Seq(3));
        assert!(recv.eof());
        assert_eq!(recv.reset_start(Seq(100)), Err(()));
    }

    #[test]
    fn in_order_text_with_fin_ends_the_stream_across_the_wrap() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 1), 8).unwrap();
        recv.insert(Seq(u32::MAX - 1), b"abcde", false);
        let mut out = [0; 8];
        assert_eq!(recv.read(&mut out[..5]), 5);
        let result = recv.insert_with_push(Seq(3), b"fghijk", true, true);
        assert_eq!(result.new_bytes, 6);
        assert!(result.fin && result.advanced && !result.out_of_order);
        assert!(recv.eof() && recv.take_push());
        assert_eq!(recv.next(), Seq(10));
        assert_eq!(recv.fin_sequence, Some(Seq(9)));
        assert!(!recv.insert(Seq(9), b"", true).fin);
        assert_eq!(recv.read(&mut out), 6);
        assert_eq!(&out[..6], b"fghijk");
        assert!(recv.metadata.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn rejects_fin_conflicts_without_destroying_accepted_bytes() {
        let mut recv = ReceiveBuffer::new(Seq(10), 8).unwrap();
        recv.insert(Seq(14), b"e", false);
        for position in [9, 12, 14, 18] {
            assert!(!recv.insert(Seq(position), b"", true).fin);
            assert_eq!(recv.fin_sequence, None);
        }
        recv.insert(Seq(15), b"", true);
        assert_eq!(recv.fin_sequence, Some(Seq(15)));
        for position in [12, 16] {
            recv.insert(Seq(position), b"", true);
            assert_eq!(recv.fin_sequence, Some(Seq(15)));
        }
        let result = recv.insert(Seq(10), b"abcde", false);
        assert!(result.fin);
        assert_eq!(recv.next(), Seq(16));
        let mut out = [0; 6];
        assert_eq!(recv.read(&mut out), 5);
        assert_eq!(&out[..5], b"abcde");

        let mut recv = ReceiveBuffer::new(Seq(0), 4).unwrap();
        recv.insert(Seq(0), b"abcd", true); // FIN at right edge is excluded.
        assert_eq!(recv.fin_sequence, None);
        assert!(!recv.insert(Seq(2), b"", true).fin);
        assert_eq!(recv.read(&mut out[..1]), 1);
        let result = recv.insert(Seq(4), b"", true);
        assert!(result.fin && result.advanced);
        assert_eq!(recv.readable(), 3);
    }

    #[test]
    fn reading_preserves_out_of_order_data_and_pending_fin() {
        let mut recv = ReceiveBuffer::new(Seq(10), 6).unwrap();
        recv.insert(Seq(14), b"e", true);
        recv.insert(Seq(10), b"ab", false);
        let mut out = [0; 6];
        assert_eq!(recv.read(&mut out), 2);
        assert_eq!(&out[..2], b"ab");
        assert_eq!(recv.next(), Seq(12));
        assert_eq!(recv.right_edge(), Seq(18));
        assert_eq!(recv.insert(Seq(15), b"xyz", false).new_bytes, 0);
        let completed = recv.insert(Seq(12), b"cd", false);
        assert!(completed.fin && completed.advanced);
        assert_eq!(recv.read(&mut out), 3);
        assert_eq!(&out[..3], b"cde");
        assert_eq!(recv.next(), Seq(16));
    }

    #[test]
    fn adversarial_gaps_have_fixed_storage() {
        let mut recv = ReceiveBuffer::new(Seq(0), 64).unwrap();
        let data_storage = (recv.data.as_ptr(), recv.data.capacity());
        let metadata_storage = (recv.metadata.as_ptr(), recv.metadata.capacity());
        for offset in (1..64).step_by(2) {
            assert_eq!(
                recv.insert(Seq(offset), &[offset as u8], false).new_bytes,
                1
            );
        }
        assert_eq!(recv.readable(), 0);
        assert_eq!(
            (0..recv.data.len()).filter(|&i| recv.is_present(i)).count(),
            32
        );
        for offset in (0..64).step_by(2) {
            assert_eq!(
                recv.insert(Seq(offset), &[offset as u8], false).new_bytes,
                1
            );
        }
        assert_eq!(recv.readable(), 64);
        assert_eq!(
            (0..recv.data.len()).filter(|&i| recv.is_present(i)).count(),
            64
        );
        let mut out = [0; 64];
        assert_eq!(recv.read(&mut out), 64);
        for (offset, &byte) in out.iter().enumerate() {
            assert_eq!(byte, offset as u8);
        }
        assert_eq!((recv.data.as_ptr(), recv.data.capacity()), data_storage);
        assert_eq!(
            (recv.metadata.as_ptr(), recv.metadata.capacity()),
            metadata_storage
        );
    }

    #[test]
    fn empty_presence_and_constant_time_data_presence_agree() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 8), 8192).unwrap();
        assert!(recv.metadata.iter().all(|&value| value == 0));
        assert!(!recv.has_data());
        assert_eq!(recv.reset_start(Seq(10)), Ok(()));
        recv.insert(Seq(12), b"cd", false);
        assert!(recv.has_data());
        assert_eq!(recv.reset_start(Seq(20)), Err(()));
        recv.insert(Seq(10), b"ab", false);
        assert!(recv.has_data());
        assert_eq!(recv.read(&mut [0; 4]), 4);
        assert!(!recv.has_data());
        assert!(recv.metadata.iter().all(|&value| value == 0));
        assert_eq!(recv.reset_start(Seq(20)), Ok(()));
    }

    #[test]
    fn byte_bitset_exact_capacity_wrap_overlap_push_and_fin() {
        for capacity in (1..=9).chain([15, 17, 63, 65, 70, 127, 129]) {
            let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 3), capacity).unwrap();
            assert_eq!(recv.data.len(), capacity);
            assert_eq!(core::mem::size_of_val(recv.data.as_slice()), capacity);
            assert_eq!(recv.metadata.len(), capacity.div_ceil(4));
            assert!(
                core::mem::size_of_val(recv.data.as_slice()) + recv.metadata.len() <= 3 * capacity
            );
            let storage = (recv.data.as_ptr(), recv.metadata.as_ptr());
            let payload: Vec<_> = (0..capacity).map(|i| i as u8).collect();
            let mut out = alloc::vec![0; capacity];
            for _ in 0..3 {
                let start = recv.next();
                assert_eq!(recv.right_edge(), start.wrapping_add(capacity as u32));
                let last = start.wrapping_add(capacity as u32 - 1);
                recv.insert_with_push(last, &payload[capacity - 1..], false, true);
                // Duplicate PSH changes only the mark, not the stored byte.
                assert_eq!(recv.insert_with_push(last, b"!", false, true).new_bytes, 0);
                recv.insert(start, &payload, false);
                assert!(recv.take_push());
                assert!(!recv.take_push());
                assert_eq!(recv.insert(recv.right_edge(), b"!", false).new_bytes, 0);
                assert_ranges(&recv);
                // Moving the head by one crosses bit-byte and ring boundaries
                // over successive cycles; cleared slots must be fully rewritten.
                assert_eq!(recv.read(&mut out[..1]), 1);
                assert_eq!(out[0], payload[0]);
                let next = recv.next();
                assert_eq!(recv.insert(next, b"z", false).new_bytes, 1);
                assert!(!recv.take_push());
                assert_eq!(recv.read(&mut out), capacity);
                assert_eq!(&out[..capacity - 1], &payload[1..]);
                assert_eq!(out[capacity - 1], b'z');
                assert!(recv.metadata.iter().all(|&byte| byte == 0));
                assert!(!recv.has_data());
                assert_eq!((recv.data.as_ptr(), recv.metadata.as_ptr()), storage);
            }
            let start = recv.next();
            let fin = start.wrapping_add(capacity as u32 - 1);
            recv.insert(fin, b"", true);
            recv.insert_with_push(start, &payload[..capacity - 1], false, true);
            assert!(recv.eof());
            assert_eq!(recv.next(), fin.wrapping_add(1));
            assert_eq!(recv.read(&mut out), capacity - 1);
            assert_eq!(&out[..capacity - 1], &payload[..capacity - 1]);
            assert!(recv.metadata.iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn peek_preserves_credit_frontiers_metadata_and_wraparound() {
        let mut recv = ReceiveBuffer::new(Seq(100), 8).unwrap();
        recv.insert(Seq(100), b"abcdef", false);
        assert_eq!(recv.read(&mut [0; 5]), 5);
        recv.insert(Seq(106), b"ghij", false);
        recv.insert(Seq(112), b"z", false); // Out-of-order byte is not readable.
        let before = alloc::format!("{recv:?}");
        let mut out = [0; 16];
        for _ in 0..2 {
            assert_eq!(recv.peek(&mut out), 5);
            assert_eq!(&out[..5], b"fghij");
            assert_eq!(alloc::format!("{recv:?}"), before);
        }
        assert_eq!(recv.read(&mut out), 5);
        assert_eq!(&out[..5], b"fghij");
        assert_eq!(recv.peek(&mut out), 0);
    }

    #[test]
    #[should_panic]
    fn read_checks_presence_before_accessing_uninitialized_byte() {
        let mut recv = ReceiveBuffer::new(Seq(0), 1).unwrap();
        // Deliberately break the frontier invariant: read must still reject a
        // hole before it could read an uninitialized u8.
        recv.contiguous_len = 1;
        recv.read(&mut [0]);
    }

    #[test]
    fn empty_reset_and_outcome_flags() {
        assert!(ReceiveBuffer::new(Seq(0), 0).is_err());
        assert!(ReceiveBuffer::new(Seq(0), 1usize << 31).is_err());
        assert!(ReceiveBuffer::new(Seq(0), usize::MAX).is_err());
        let mut recv = ReceiveBuffer::new(Seq(0), 2).unwrap();
        assert_eq!(recv.reset_start(Seq(10)), Ok(()));
        let result = recv.insert(Seq(42), b"", false);
        assert_eq!(result.new_bytes, 0);
        assert!(!result.advanced && !result.fin && !result.out_of_order);
        assert_eq!(recv.next(), Seq(10));
        let rejected = recv.insert(Seq(42), b"x", false);
        assert!(rejected.out_of_order);
        assert_eq!(rejected.new_bytes, 0);
        recv.insert(Seq(11), b"b", false);
        assert_eq!(recv.reset_start(Seq(20)), Err(()));
        recv.insert(Seq(10), b"a", false);
        assert_eq!(recv.reset_start(Seq(20)), Err(()));
        assert_eq!(recv.read(&mut []), 0);
        assert_eq!(recv.read(&mut [0; 2]), 2);
        assert_eq!(recv.reset_start(Seq(20)), Ok(()));
        assert_eq!(recv.next(), Seq(20));
        recv.insert(Seq(21), b"", true);
        assert_eq!(recv.reset_start(Seq(30)), Err(()));

        let mut recv = ReceiveBuffer::new(Seq(7), 1).unwrap();
        let result = recv.insert(Seq(7), b"", true);
        assert!(result.fin && result.advanced);
        assert!(!result.out_of_order);
        assert_eq!(recv.next(), Seq(8));
        assert_eq!(recv.read(&mut [0]), 0);
    }
    #[test]
    fn push_marks_remain_bounded_across_gaps_overlaps_and_slot_reuse() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 1), 64).unwrap();
        let storage = (recv.data.as_ptr(), recv.data.capacity());
        for cycle in 0..3 {
            let start = recv.next();
            for offset in (1..64).step_by(2) {
                recv.insert_with_push(start.wrapping_add(offset), b"x", false, true);
                assert!(!recv.take_push());
            }
            for offset in (0..64).step_by(2) {
                recv.insert_with_push(start.wrapping_add(offset), b"y", false, false);
                assert!(recv.take_push());
            }
            assert!(!recv.take_push());
            assert_eq!(recv.read(&mut [0; 64]), 64);
            assert_eq!(
                (recv.data.as_ptr(), recv.data.capacity()),
                storage,
                "cycle {cycle}"
            );
        }
        let start = recv.next();
        recv.insert_with_push(start.wrapping_add(3), b"d", false, false);
        recv.insert_with_push(start.wrapping_add(2), b"cd", false, true);
        assert!(!recv.take_push()); // New c carries a mark ending on already queued d.
        recv.insert_with_push(start, b"ab", false, false);
        assert!(recv.take_push());
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.3
    //= type=test
    //# A TCP receiver MAY pass a received PSH bit to the application layer via
    //# the PUSH flag in the interface (MAY-17), but it is not required
    fn duplicate_out_of_order_text_can_introduce_push() {
        for start in [Seq(100), Seq(u32::MAX - 3)] {
            let mut recv = ReceiveBuffer::new(start, 8).unwrap();
            let storage = (recv.data.as_ptr(), recv.data.capacity());
            recv.insert_with_push(start.wrapping_add(4), b"efgh", false, false);
            let duplicate = recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
            assert_eq!(duplicate.new_bytes, 0);
            assert!(!recv.take_push());
            recv.insert_with_push(start, b"abcd", false, false);
            assert!(recv.take_push());
            assert!(!recv.take_push());
            recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
            assert!(!recv.take_push()); // Already contiguous, even before read.
            let mut out = [0; 8];
            assert_eq!(recv.read(&mut out), 8);
            assert_eq!(&out, b"abcdefgh");
            recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
            recv.insert_with_push(recv.next(), b"", false, true);
            assert!(!recv.take_push());
            assert_eq!((recv.data.as_ptr(), recv.data.capacity()), storage);
        }
    }

    #[test]
    fn duplicate_push_ignores_trimmed_endpoints_and_preserves_fin_conflicts() {
        let mut recv = ReceiveBuffer::new(Seq(100), 8).unwrap();
        recv.insert(Seq(104), b"efgh", false);
        recv.insert_with_push(Seq(104), b"efghi", false, true);
        recv.insert_with_push(Seq(106), b"", true, true); // FIN conflicts with gh.
        assert_eq!(recv.fin_sequence, None);
        recv.insert(Seq(100), b"abcd", false);
        assert!(!recv.take_push());
        assert_eq!(recv.read(&mut [0; 8]), 8);

        let mut recv = ReceiveBuffer::new(Seq(100), 8).unwrap();
        recv.insert(Seq(104), b"ef", true); // Pending FIN at 106.
        recv.insert_with_push(Seq(104), b"efgh", false, true);
        assert_eq!(recv.fin_sequence, Some(Seq(106)));
        recv.insert(Seq(100), b"abcd", false);
        assert!(!recv.take_push()); // Endpoint beyond FIN was trimmed.
        assert!(recv.eof());
        assert_eq!(recv.read(&mut [0; 8]), 6);
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

    // Everything a receive ring holds, by offset from read_base: two rings
    // that agree here behave alike whatever their physical layout.
    fn logical(recv: &ReceiveBuffer) -> alloc::string::String {
        let slots: Vec<_> = (0..recv.capacity())
            .map(|offset| {
                let index = recv.index(offset);
                (
                    // Only occupied slots have initialized bytes.
                    recv.is_present(index)
                        .then(|| unsafe { recv.data[index].assume_init() }),
                    recv.is_push(index),
                    recv.report_pending[index / 8] & (1 << (index % 8)) != 0,
                )
            })
            .collect();
        alloc::format!(
            "{:?}",
            (
                (recv.capacity(), recv.next(), recv.readable(), recv.occupied),
                (recv.fin_sequence, recv.eof, recv.pushed, recv.deferred_syn),
                (
                    recv.latest,
                    recv.reported,
                    recv.report_debt,
                    recv.pending_first
                ),
                (recv.dsack, recv.sack_blocks(4), slots),
            )
        )
    }

    #[test]
    fn receive_growth_in_place_matches_a_copied_ring_across_wraps() {
        let byte = |seq: Seq| (seq.0 as u8) ^ 0x5a;
        let mut state = 0x2545_f491_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        // Growths that kept head where it was (the wrapped prefix moved past
        // the old end) and that moved it (the rest moved to the new end).
        let (mut kept, mut moved) = (0, 0);
        for initial in [9, 13, 24, 64, 100] {
            let start = Seq(u32::MAX - 50);
            let mut recv = ReceiveBuffer::new(start, initial).unwrap();
            let mut reference = ReceiveBuffer::new(start, initial).unwrap();
            for _ in 0..2000 {
                let capacity = recv.capacity();
                match next(10) {
                    0..=4 => {
                        let sequence = recv
                            .next()
                            .wrapping_add((next(capacity + 24) as u32).wrapping_sub(8));
                        let payload: Vec<u8> = (0..next(40))
                            .map(|i| byte(sequence.wrapping_add(i as u32)))
                            .collect();
                        let (fin, push) = (next(60) == 0, next(3) == 0);
                        for buffer in [&mut recv, &mut reference] {
                            buffer.record_duplicate(sequence, payload.len());
                        }
                        let outcome = recv.insert_with_push(sequence, &payload, fin, push);
                        let expected = reference.insert_with_push(sequence, &payload, fin, push);
                        assert_eq!(
                            alloc::format!("{outcome:?}"),
                            alloc::format!("{expected:?}")
                        );
                    }
                    5 | 6 => {
                        let base = recv.read_base;
                        let mut out = alloc::vec![0; next(capacity + 1)];
                        let mut expected = out.clone();
                        let count = recv.read(&mut out);
                        assert_eq!(reference.read(&mut expected), count);
                        assert_eq!(out, expected);
                        for (offset, &value) in out[..count].iter().enumerate() {
                            assert_eq!(value, byte(base.wrapping_add(offset as u32)));
                        }
                    }
                    7 => {
                        for buffer in [&mut recv, &mut reference] {
                            if let Some(first) = buffer.sack_blocks(4)[0] {
                                buffer.commit_sack(first);
                            }
                            buffer.commit_report();
                        }
                    }
                    _ if capacity >= 1024 => {
                        // Start over small, so that growth keeps being tried.
                        let start = recv.next();
                        recv = ReceiveBuffer::new(start, initial).unwrap();
                        reference = ReceiveBuffer::new(start, initial).unwrap();
                    }
                    _ => {
                        // Small steps leave too little room past the old end
                        // for the wrapped prefix; large ones take it whole.
                        let step = if next(2) == 0 { 8 } else { 2 * capacity };
                        let target = capacity + 1 + next(step);
                        let head = recv.head;
                        recv.grow(target).unwrap();
                        let rounded = target.next_multiple_of(8);
                        assert_eq!(recv.capacity(), rounded);
                        reference = reference.grown(rounded).unwrap();
                        if head != 0 && recv.head == head {
                            kept += 1;
                        } else if head != 0 {
                            moved += 1;
                        }
                    }
                }
                if recv.eof() {
                    let next = recv.next();
                    for buffer in [&mut recv, &mut reference] {
                        buffer.clear();
                        buffer.reset_start(next).unwrap();
                    }
                }
                assert_eq!(logical(&recv), logical(&reference));
                assert_ranges(&recv);
            }
        }
        assert!(kept > 50 && moved > 50, "{kept} {moved}");
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
        let mut wrapped = 0;
        for step in 0..4000 {
            match next(5) {
                0 | 1 => {
                    let input: Vec<u8> = (0..next(100)).map(|i| (step + i) as u8).collect();
                    let count = send.write(&input);
                    assert_eq!(count, input.len().min(send.capacity() - model.len()));
                    model.extend(input[..count].iter().map(|&b| (b, 0)));
                }
                2 => {
                    let count = next(model.len() + 1);
                    send.acknowledge(count).unwrap();
                    model.drain(..count);
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
        }
        assert!(wrapped > 20, "{wrapped}");
    }

    #[test]
    fn failed_growth_leaves_rings_unchanged_and_retry_reuses_storage() {
        use crate::allocation_tests::fail_after;
        // A wrapped receive ring with a hole, PUSH, a pending FIN and
        // pending reports.
        let start = Seq(u32::MAX - 5);
        let mut recv = ReceiveBuffer::new(start, 21).unwrap();
        recv.insert(start, &[1; 15], false);
        assert_eq!(recv.read(&mut [0; 15]), 15);
        let base = recv.next();
        recv.insert_with_push(base, b"abc", false, true);
        recv.insert_with_push(base.wrapping_add(8), b"defghij", true, true);
        recv.record_duplicate(base.wrapping_add(9), 2);
        let before = logical(&recv);
        let storage = recv.storage_bytes();
        // Each attempt fails at the payload, the presence bitmap or the
        // report bitmap, the later ones after earlier reservations held.
        // The chunk summaries of so small a ring allocate nothing.
        for allocation in [0, 1, 1, 0] {
            assert_eq!(fail_after(allocation, || recv.grow(100)), Err(()));
            assert_eq!(logical(&recv), before);
            assert_ranges(&recv);
        }
        assert!(recv.storage_bytes() > storage);
        // Neither a ring already as large nor one too large to address
        // allocates: the first allocation after them still fails.
        assert!(fail_after(0, || recv.grow(21) == Ok(())
            && recv.grow((1 << 31) - 1) == Err(())
            && SendBuffer::new(1).is_err()));
        let reference = recv.grown(104).unwrap();
        // Only the report bitmap is left to reserve.
        assert_eq!(fail_after(1, || recv.grow(100)), Ok(()));
        assert_eq!(recv.capacity(), 104);
        assert_eq!(logical(&recv), logical(&reference));
        recv.insert(base.wrapping_add(3), b"12345", false);
        assert!(recv.eof());
        let mut out = [0; 32];
        assert_eq!(recv.read(&mut out), 15);
        assert_eq!(&out[..15], b"abc12345defghij");
        assert!(recv.take_push());

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
