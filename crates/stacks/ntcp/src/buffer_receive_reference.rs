// The receive ring as it was before the contiguous prefix stopped keeping
// presence bits (ntcp b0d2988, buffer.rs), verbatim but for its name: the
// randomized equivalence test runs it in lockstep with ReceiveBuffer.
#![allow(dead_code)]
use super::*;

#[derive(Debug)]
pub(crate) struct ReferenceReceiveBuffer {
    // A set presence bit implies the payload byte in that slot was initialized.
    // Every typed payload read checks presence first; clearing presence makes
    // the slot inaccessible until insertion writes a new byte before setting it.
    // Unset slots may contain uninitialized bytes; they are never read as u8.
    pub(crate) data: Vec<MaybeUninit<u8>>,
    pub(crate) pushed: bool,
    pub(crate) metadata: Vec<u8>,
    // Chunks of `metadata` holding a present slot, and chunks missing one.
    pub(crate) holding: ChunkSummary,
    pub(crate) missing: ChunkSummary,
    pub(crate) read_base: Seq,
    pub(crate) head: usize,
    pub(crate) contiguous_len: usize,
    // Initialized prefix in the existing ring, not yet admitted to receive state.
    pub(crate) deferred_syn: Option<(usize, bool, bool)>,
    pub(crate) fin_sequence: Option<Seq>,
    pub(crate) eof: bool,
    pub(crate) occupied: usize,
    pub(crate) latest: Option<Seq>,
    pub(crate) reported: [Option<Seq>; 4],
    // One first-new-byte anchor per arrival, independent of wire history.
    // Input never allocates reporting work; application-read anchors become
    // cumulative-only debt, bounded by capacity even if output is exhausted.
    pub(crate) report_pending: Vec<u8>,
    pub(crate) report_debt: usize,
    pub(crate) pending_first: Option<Seq>,
    pub(crate) dsack: Option<(Seq, Seq)>,
}

impl ReferenceReceiveBuffer {
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
        // Nothing is retained beyond the contiguous prefix, so data at or
        // above the frontier duplicates nothing: as Linux tcp_data_queue sets
        // a D-SACK only below rcv_nxt or over its out-of-order queue.
        if self.occupied == self.contiguous_len {
            debug_assert!(
                self.find_presence(self.contiguous_len + start as usize, true) == self.data.len()
            );
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
        let any = self.dsack.is_some() || self.occupied > self.contiguous_len;
        debug_assert!(any || self.walk_sack_blocks(4) == [None; 4]);
        any
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
        if !self.has_sack_blocks() {
            return [None; 4];
        }
        self.walk_sack_blocks(max_blocks)
    }

    pub(crate) fn walk_sack_blocks(&self, max_blocks: usize) -> [Option<(u32, u32)>; 4] {
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

    pub(crate) fn pending(&self, seq: Seq) -> bool {
        let offset = seq.distance_from(self.read_base) as usize;
        offset < self.data.len() && {
            let index = self.index(offset);
            self.report_pending[index / 8] & (1 << (index % 8)) != 0
        }
    }

    pub(crate) fn report_anchor(&self) -> Option<Seq> {
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

    pub(crate) fn find_pending(&self, mut offset: usize) -> Option<Seq> {
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

    pub(crate) fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)> {
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
    pub(crate) fn find_presence(&self, offset: usize, present: bool) -> usize {
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
    pub(crate) fn chunk_presence(&self, chunk: usize) -> (u64, u64) {
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
    pub(crate) fn chunk_matching(&self, chunk: usize, present: bool) -> u64 {
        let (word, valid) = self.chunk_presence(chunk);
        if present { word } else { valid & !word }
    }

    pub(crate) fn summary(&self, present: bool) -> &ChunkSummary {
        if present {
            &self.holding
        } else {
            &self.missing
        }
    }

    // The first slot of physical `range` whose presence is `present`.
    pub(crate) fn find_slot(&self, range: core::ops::Range<usize>, present: bool) -> Option<usize> {
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
    pub(crate) fn find_slot_back(
        &self,
        range: core::ops::Range<usize>,
        present: bool,
    ) -> Option<usize> {
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
    pub(crate) fn summarize(&mut self, range: core::ops::Range<usize>) {
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
    pub(crate) fn summarize_filled(&mut self, range: core::ops::Range<usize>, present: bool) {
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
    pub(crate) fn summarize_logical(&mut self, offset: usize, len: usize) {
        for range in self.ranges(offset, len) {
            self.summarize(range);
        }
    }

    pub(crate) fn index(&self, offset: usize) -> usize {
        (self.head + offset) % self.data.len()
    }

    // Each slot uses a presence bit followed by a PUSH bit, four slots per byte.
    pub(crate) fn is_present(&self, index: usize) -> bool {
        self.metadata[index / 4] & (1 << (2 * (index % 4))) != 0
    }

    pub(crate) fn set_present(&mut self, index: usize, present: bool) {
        let shift = 2 * (index % 4);
        // Both insertion and removal clear stale PUSH marks on reused slots.
        self.metadata[index / 4] =
            (self.metadata[index / 4] & !(3 << shift)) | (u8::from(present) << shift);
    }

    pub(crate) fn is_push(&self, index: usize) -> bool {
        self.metadata[index / 4] & (2 << (2 * (index % 4))) != 0
    }

    pub(crate) fn set_push(&mut self, index: usize, push: bool) {
        let mask = 2 << (2 * (index % 4));
        if push {
            self.metadata[index / 4] |= mask;
        } else {
            self.metadata[index / 4] &= !mask;
        }
    }

    // The slots of `len` bytes from `offset`, as at most two index ranges
    // (the second one after the ring wraps).
    pub(crate) fn ranges(&self, offset: usize, len: usize) -> [core::ops::Range<usize>; 2] {
        let start = self.index(offset);
        let first = len.min(self.data.len() - start);
        [start..start + first, 0..len - first]
    }

    // `set_present` for every slot of `range`, four slots per metadata byte.
    pub(crate) fn set_present_range(&mut self, range: core::ops::Range<usize>, present: bool) {
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
    pub(crate) fn take_push_range(&mut self, range: core::ops::Range<usize>) -> bool {
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
    pub(crate) fn all_present(&self, range: core::ops::Range<usize>) -> bool {
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
    pub(crate) fn clear_pending_range(&mut self, range: core::ops::Range<usize>) {
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
