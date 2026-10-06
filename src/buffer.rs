extern crate alloc;

use alloc::{
    alloc::{Layout, alloc_zeroed},
    collections::VecDeque,
    vec::Vec,
};

use core::mem::MaybeUninit;

use crate::seq::Seq;

#[derive(Debug)]
pub(crate) struct SendBuffer {
    // One bounded push mark per byte; ACK and truncation move marks with data.
    data: VecDeque<(u8, bool)>,
    capacity: usize,
}

impl SendBuffer {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut data = VecDeque::new();
        data.try_reserve_exact(capacity).map_err(|_| ())?;
        Ok(Self { data, capacity })
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity - self.len()
    }

    pub(crate) fn write(&mut self, input: &[u8]) -> usize {
        let count = input.len().min(self.remaining());
        self.data
            .extend(input[..count].iter().map(|&byte| (byte, false)));
        count
    }

    pub(crate) fn mark_push(&mut self) {
        if let Some(last) = self.data.back_mut() {
            last.1 = true;
        }
    }

    pub(crate) fn pushed(&self, offset: usize, count: usize) -> bool {
        self.data.iter().skip(offset).take(count).any(|byte| byte.1)
    }

    pub(crate) fn collapse_push(&mut self, offset: usize, count: usize) {
        for byte in self.data.iter_mut().skip(offset).take(count) {
            byte.1 = false;
        }
        if let Some(last) = self.data.get_mut(offset + count - 1) {
            last.1 = true;
        }
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
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
        Ok(())
    }

    pub(crate) fn copy(&self, offset: usize, out: &mut [u8]) -> usize {
        let count = out.len().min(self.len().saturating_sub(offset));
        for (dst, src) in out[..count].iter_mut().zip(self.data.iter().skip(offset)) {
            *dst = src.0;
        }
        count
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

const MAX_OOO_RANGES: usize = 64;

#[derive(Clone, Copy, Debug)]
struct ReceiveRange {
    start: Seq,
    end: Seq,
    // Dense ranks: zero is newest, so no arrival counter can wrap.
    recency: u8,
}

const EMPTY_RANGE: ReceiveRange = ReceiveRange {
    start: Seq(0),
    end: Seq(0),
    recency: 0,
};

#[derive(Debug)]
pub(crate) struct ReceiveBuffer {
    // A set presence bit implies the payload byte in that slot was initialized.
    // Every typed payload read checks presence first; clearing presence makes
    // the slot inaccessible until insertion writes a new byte before setting it.
    // Unset slots may contain uninitialized bytes; they are never read as u8.
    data: Vec<MaybeUninit<u8>>,
    pushed: bool,
    metadata: Vec<u8>,
    read_base: Seq,
    head: usize,
    contiguous_len: usize,
    fin_sequence: Option<Seq>,
    eof: bool,
    ranges: [ReceiveRange; MAX_OOO_RANGES],
    range_count: usize,
    dsack: Option<(Seq, Seq)>,
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
        let metadata_len = capacity.div_ceil(4);
        let metadata_layout = Layout::array::<u8>(metadata_len).map_err(|_| ())?;
        let metadata = unsafe {
            let pointer = alloc_zeroed(metadata_layout);
            if pointer.is_null() {
                return Err(());
            }
            // Zeroed bytes clear every bit; the allocation uses Vec's exact layout.
            Vec::from_raw_parts(pointer, metadata_len, metadata_len)
        };
        Ok(Self {
            data,
            pushed: false,
            metadata,
            read_base: start,
            head: 0,
            contiguous_len: 0,
            fin_sequence: None,
            eof: false,
            ranges: [EMPTY_RANGE; MAX_OOO_RANGES],
            range_count: 0,
            dsack: None,
        })
    }

    pub(crate) fn clear(&mut self) {
        self.metadata.fill(0);
        self.pushed = false;
        self.read_base = Seq(0);
        self.head = 0;
        self.contiguous_len = 0;
        self.fin_sequence = None;
        self.eof = false;
        self.ranges.fill(EMPTY_RANGE);
        self.range_count = 0;
        self.dsack = None;
    }

    pub(crate) fn reset_start(&mut self, start: Seq) -> Result<(), ()> {
        if self.fin_sequence.is_some() || self.has_data() {
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

    pub(crate) fn has_data(&self) -> bool {
        self.contiguous_len != 0 || self.range_count != 0
    }

    pub(crate) fn take_push(&mut self) -> bool {
        core::mem::take(&mut self.pushed)
    }

    pub(crate) fn eof(&self) -> bool {
        self.eof
    }

    // Call once on the raw packet, before trimming or inserting; insertion must not
    // replace this record with one based on the trimmed payload. FIN is not data.
    // Scope: Existing SACK negotiation gates duplicate reports, no separate D-SACK capability flag or handshake option.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-2
    //= reason=Existing SACK negotiation gates duplicate reports, no separate D-SACK capability flag or handshake option.
    //# The use of D-SACK does not require separate negotiation between a TCP
    //# sender and receiver that have already negotiated SACK capability.
    // Scope: Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
    //# (1) A D-SACK block is only used to report a duplicate contiguous
    //# sequence of data received by the receiver in the most recent packet.
    // Scope: Records raw duplicate start/exclusive end before trimming, including already-read cumulative bytes and wrap.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Records raw duplicate start/exclusive end before trimming, including already-read cumulative bytes and wrap.
    //# (3) The left edge of the D-SACK block specifies the first sequence
    //# number of the duplicate contiguous sequence, and the right edge of
    //# the D-SACK block specifies the sequence number immediately following
    //# the last sequence in the duplicate contiguous sequence.
    // Scope: First raw prefix/earliest retained-range overlap wins; erratum365 fixes illustrative second arrival to 2500-2999 and existing example6 test matches it.
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
        for range in &self.ranges[..self.range_count] {
            let left = start.max(range.start.distance_from(frontier) as i64);
            let right = end.min(range.end.distance_from(frontier) as i64);
            if left < right {
                self.dsack = Some((
                    frontier.wrapping_add(left as u32),
                    frontier.wrapping_add(right as u32),
                ));
                break;
            }
        }
    }

    pub(crate) fn clear_dsack(&mut self) {
        self.dsack = None;
    }

    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Ordinary SACK selects newest contiguous retained union first, except arrivals advancing the cumulative frontier. RFC 2883 DSACK is a separate first-block extension, not asserted as ordinary RFC 2018 behavior.
    //# * The first SACK block (i.e., the one immediately following the kind and
    //# length fields in the option) MUST specify the contiguous block of data
    //# containing the segment which triggered this ACK, unless that segment
    //# advanced the Acknowledgment Number field in the header.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Retained distinct ranges have dense arrival-recency ranks; focused RFC examples check repeated blocks and subset-eliminating merge.
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
    // Scope: D-SACK alters option contents only; cumulative ACK still follows receive frontier and ACK scheduling remains normal TCP.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-2
    //= reason=D-SACK alters option contents only; cumulative ACK still follows receive frontier and ACK scheduling remains normal TCP.
    //# This document does not make any changes to TCP's use of the
    //# cumulative acknowledgement field, or to the TCP receiver's decision
    //# of *when* to send an acknowledgement packet.
    // Scope: Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
    //# (4) If the D-SACK block reports a duplicate contiguous sequence from
    //# a (possibly larger) block of data in the receiver's data queue above
    //# the cumulative acknowledgement, then the second SACK block in that
    //# SACK option should specify that (possibly larger) block of data.
    // Scope: Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= reason=Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
    //# (5) Following the SACK blocks described above for reporting duplicate
    //# segments, additional SACK blocks can be used for reporting additional
    //# blocks of data, as specified in RFC 2018.
    // Scope: Pending raw duplicate occupies first block, ahead of containing/other ordinary SACK ranges; option budget may decline duplicate report, not mislabel an ordinary block as DSACK.
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
        let mut containing = None;
        if let Some((start, end)) = self.dsack {
            blocks[count] = Some((start.0, end.0));
            count += 1;
            containing = self.ranges[..self.range_count].iter().position(|range| {
                let offset = start.distance_from(range.start);
                offset < range.end.distance_from(range.start)
                    && end.distance_from(range.start) <= range.end.distance_from(range.start)
            });
            // An above-ACK duplicate is distinguishable only with a containing
            // second block. With one slot, send that full ordinary SACK instead.
            if let Some(index) = containing
                && limit == 1
            {
                let range = self.ranges[index];
                blocks[0] = Some((range.start.0, range.end.0));
                return blocks;
            }
            if let Some(index) = containing
                && count < limit
            {
                let range = self.ranges[index];
                blocks[count] = Some((range.start.0, range.end.0));
                count += 1;
            }
        }
        for recency in 0..self.range_count {
            if count == limit {
                break;
            }
            for (index, range) in self.ranges[..self.range_count].iter().enumerate() {
                if range.recency as usize == recency && Some(index) != containing {
                    blocks[count] = Some((range.start.0, range.end.0));
                    count += 1;
                    break;
                }
            }
        }
        blocks
    }

    fn remove_range(&mut self, index: usize) {
        let recency = self.ranges[index].recency;
        self.ranges.copy_within(index + 1..self.range_count, index);
        self.range_count -= 1;
        for range in &mut self.ranges[..self.range_count] {
            if range.recency > recency {
                range.recency -= 1;
            }
        }
    }

    // Preflight the union before touching presence/data. A span at the frontier
    // consumes ranges instead of needing a temporary 65th slot.
    fn track_range(&mut self, mut left: usize, mut right: usize) -> bool {
        let mut first = 0;
        while first < self.range_count
            && (self.ranges[first].end.distance_from(self.read_base) as usize) < left
        {
            first += 1;
        }
        let mut last = first;
        while last < self.range_count
            && (self.ranges[last].start.distance_from(self.read_base) as usize) <= right
        {
            left = left.min(self.ranges[last].start.distance_from(self.read_base) as usize);
            right = right.max(self.ranges[last].end.distance_from(self.read_base) as usize);
            last += 1;
        }
        let contiguous = left == self.contiguous_len;
        if self.range_count - (last - first) + usize::from(!contiguous) > MAX_OOO_RANGES {
            return false;
        }
        for _ in first..last {
            self.remove_range(first);
        }
        if !contiguous {
            self.ranges.copy_within(first..self.range_count, first + 1);
            for range in &mut self.ranges[..self.range_count + 1] {
                range.recency += 1;
            }
            self.ranges[first] = ReceiveRange {
                start: self.read_base.wrapping_add(left as u32),
                end: self.read_base.wrapping_add(right as u32),
                recency: 0,
            };
            self.range_count += 1;
        }
        true
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

    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.contiguous_len);
        for (offset, dst) in out[..count].iter_mut().enumerate() {
            let index = self.index(offset);
            assert!(self.is_present(index));
            // Presence guarantees an initialized payload byte.
            *dst = unsafe { self.data[index].assume_init() };
            self.set_present(index, false);
        }
        self.head = self.index(count);
        self.read_base = self.read_base.wrapping_add(count as u32);
        self.contiguous_len -= count;
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
        let previous_next = self.next();
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
        let start = sequence.distance_from(self.read_base) as i32 as i64;
        let left = start.max(self.contiguous_len as i64);
        let right = (start + payload.len() as i64).min(data_limit as i64);
        if left < right {
            outcome.sack_overflow = !self.track_range(left as usize, right as usize);
        }
        for (offset, &byte) in payload.iter().enumerate() {
            let position = sequence.wrapping_add(offset as u32);
            let distance = position.distance_from(self.read_base) as usize;
            if distance >= data_limit {
                continue;
            }
            let index = self.index(distance);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
            //# If a segment's contents straddle the boundary between old and new, only the
            //# new parts are processed.
            if !outcome.sack_overflow && !self.is_present(index) {
                self.data[index].write(byte);
                self.set_present(index, true);
                outcome.new_bytes += 1;
            }
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
            // ponytail: O(capacity) on a new FIN; track the highest occupied
            // position if this scan becomes material. Never erase accepted data.
            if distance < capacity
                && !(distance..capacity).any(|offset| self.is_present(self.index(offset)))
            {
                self.fin_sequence = Some(end);
            }
        }
        while self.contiguous_len < capacity && self.is_present(self.index(self.contiguous_len)) {
            let index = self.index(self.contiguous_len);
            self.pushed |= self.is_push(index);
            self.set_push(index, false);
            self.contiguous_len += 1;
        }
        // This buffer consumes FIN once after preceding data; SYN processing is in the
        // connection.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //# one and only one copy of the control will be acted upon
        if self.fin_sequence == Some(self.next()) {
            self.eof = true;
            outcome.fin = true;
        }
        outcome.advanced = self.next() != previous_next;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_packet(recv: &mut ReceiveBuffer, sequence: Seq, payload: &[u8]) -> ReceiveOutcome {
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
        let actual: Vec<_> = recv.ranges[..recv.range_count]
            .iter()
            .map(|r| (r.start, r.end))
            .collect();
        assert_eq!(actual, expected);
        let mut ranks: Vec<_> = recv.ranges[..recv.range_count]
            .iter()
            .map(|r| r.recency as usize)
            .collect();
        ranks.sort_unstable();
        assert_eq!(ranks, (0..recv.range_count).collect::<Vec<_>>());
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
    //= reason=Retained distinct ranges have dense arrival-recency ranks; focused RFC examples check repeated blocks and subset-eliminating merge.
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
    // Scope: Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
    //# (1) A D-SACK block is only used to report a duplicate contiguous
    //# sequence of data received by the receiver in the most recent packet.
    // Scope: Records raw duplicate start/exclusive end before trimming, including already-read cumulative bytes and wrap.
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
    // Scope: Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
    //# (4) If the D-SACK block reports a duplicate contiguous sequence from
    //# a (possibly larger) block of data in the receiver's data queue above
    //# the cumulative acknowledgement, then the second SACK block in that
    //# SACK option should specify that (possibly larger) block of data.
    // Scope: Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
    //= https://www.rfc-editor.org/rfc/rfc2883#section-4
    //= type=test
    //= reason=Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
    //# (5) Following the SACK blocks described above for reporting duplicate
    //# segments, additional SACK blocks can be used for reporting additional
    //# blocks of data, as specified in RFC 2018.
    // Scope: First raw prefix/earliest retained-range overlap wins; erratum365 fixes illustrative second arrival to 2500-2999 and existing example6 test matches it.
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
    fn overflow_is_transactional_and_bridging_at_capacity_succeeds() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 64), 256).unwrap();
        let start = recv.next();
        for offset in (1..128).step_by(2) {
            assert_eq!(
                receive_packet(&mut recv, start.wrapping_add(offset), b"a").new_bytes,
                1
            );
        }
        assert_eq!(recv.range_count, 64);
        let old_blocks = recv.sack_blocks(4);
        let old_data = occupied_data(&recv);
        let old_metadata = recv.metadata.clone();
        recv.record_duplicate(start.wrapping_add(130), 3);
        let rejected = recv.insert_with_push(start.wrapping_add(130), b"xyz", true, true);
        assert!(rejected.sack_overflow);
        assert_eq!(recv.fin_sequence, Some(start.wrapping_add(133)));
        assert!(!rejected.fin && !rejected.advanced && !recv.take_push());
        assert_eq!(rejected.new_bytes, 0);
        assert_eq!(occupied_data(&recv), old_data);
        assert_eq!(recv.metadata, old_metadata);
        assert_eq!(recv.sack_blocks(4), old_blocks);
        let bridge = receive_packet(&mut recv, start.wrapping_add(2), b"z");
        assert!(!bridge.sack_overflow);
        assert_eq!(bridge.new_bytes, 1);
        assert_eq!(recv.range_count, 63);
        receive_packet(&mut recv, start.wrapping_add(130), b"x");
        assert_eq!(recv.range_count, 64);
        assert!(!receive_packet(&mut recv, start, b"b").sack_overflow);
        assert_eq!(recv.next(), start.wrapping_add(4));
        assert_ranges(&recv);
        let result = receive_packet(&mut recv, start.wrapping_add(4), &[b'c'; 127]);
        assert!(!result.sack_overflow);
        assert_eq!(recv.range_count, 0);
        assert_ranges(&recv);
        let mut out = [0; 131];
        assert_eq!(recv.read(&mut out), 131);
        assert_eq!(&out[..4], b"baza");
        for offset in (5..128).step_by(2) {
            assert_eq!(out[offset], b'a');
        }
        assert_eq!(out[130], b'x');
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
}
