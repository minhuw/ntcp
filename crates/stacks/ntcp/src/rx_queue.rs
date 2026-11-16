// The receive queue: received payload held as frames, charged by what it
// holds, as Linux keeps skbs on sk_receive_queue (in order) and in the
// out-of-order rbtree, each charged its truesize to sk_rmem_alloc.
//
// In-order data is a deque of frames, read from the front; a frame is
// released when its last byte is read (Linux tcp_eat_recv_skb). Data
// beyond a gap is a BTreeMap of non-overlapping entries keyed by stream
// offset, beside the maximal contiguous runs they form, which answer the
// SACK, D-SACK and FIN queries in one lookup. Report anchors (one per
// out-of-order arrival, at its first new byte) are a set of offsets.
// Offsets are u64 stream offsets from the queue's start; sequence numbers
// are converted at the edge, so the maps never compare wrapped sequences.
// An empty queue holds no heap storage.
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::mem::size_of;
use ntcp_buffer::RxFrame;

use crate::seq::Seq;

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
    // The allocator refused the memory to hold the new text: nothing of the
    // segment was taken, and the queue is as it was.
    pub refused: bool,
}

// Accepted payload: borrowed from the segment, copied into a heap frame
// (truesize = length) for the part the queue keeps, or a frame the queue
// takes as it is.
pub(crate) enum RxPayload<'a> {
    Borrowed(&'a [u8]),
    Owned(RxFrame),
}

impl RxPayload<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(frame) => frame,
        }
    }

    fn len(&self) -> usize {
        self.bytes().len()
    }

    // The frame holding bytes `from..to` of the payload: a borrowed
    // payload is copied into a heap frame of that length, whose allocation
    // may be refused.
    fn into_frame(self, from: usize, to: usize) -> Result<RxFrame, ()> {
        match self {
            Self::Borrowed(bytes) => heap_copy(&bytes[from..to]),
            Self::Owned(mut frame) => {
                frame.truncate(to);
                frame.advance(from);
                Ok(frame)
            }
        }
    }
}

// A heap frame holding a copy of `bytes`, allocated to their length, or
// none if the allocator refuses it.
pub(crate) fn heap_copy(bytes: &[u8]) -> Result<RxFrame, ()> {
    let mut copy = alloc::vec::Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|_| ())?;
    copy.extend_from_slice(bytes);
    Ok(RxFrame::from_vec(copy))
}

// An entry beyond a gap: its frame, and whether a PUSH mark lies in it.
struct OfoSeg {
    frame: RxFrame,
    push: bool,
}

// The heap bytes of one BTreeMap node with `pair`-byte entries, an
// internal node's (std's B = 6: 11 entries, 12 edges, parent pointer,
// index and length) and so at least a leaf's.
const fn node_bytes(pair: usize) -> usize {
    16 + 11 * pair + 12 * size_of::<usize>()
}

// What a BTreeMap of `len` entries of `pair` bytes holds at most: its root,
// and one node per 5 entries beyond it, as std keeps every other node at
// least 5 entries full.
const fn map_bytes(len: usize, pair: usize) -> usize {
    if len == 0 {
        0
    } else {
        node_bytes(pair) * (1 + len / 5)
    }
}

const OFO_PAIR: usize = size_of::<u64>() + size_of::<OfoSeg>();
const RUN_PAIR: usize = 2 * size_of::<u64>();
const ANCHOR_PAIR: usize = size_of::<u64>();

// The truesize every held entry adds to its frame's (`rmem`), as Linux's
// SKB_TRUESIZE adds struct sk_buff: an in-order slot, plus an out-of-order
// node's share at minimum occupancy, rounded to a cache line. Constant, so
// that the window never depends on the deque's or the map's allocation
// history.
pub(crate) const RX_ENTRY_TRUESIZE: usize =
    (size_of::<RxFrame>() + node_bytes(OFO_PAIR).div_ceil(5)).next_multiple_of(64);

#[derive(Clone, Copy)]
pub(crate) struct RxOutputUndo {
    reported: [Option<Seq>; 4],
    dsack: Option<(Seq, Seq)>,
    report_debt: usize,
    pending_first: Option<Seq>,
    // The anchor the output consumed.
    anchor: Option<u64>,
}

// SYN data held until the handshake is validated: its frame (none if
// empty), length, FIN and PUSH.
type DeferredSyn = (Option<RxFrame>, usize, bool, bool);

// The received frame an input lends the queue (`Endpoint::input_frame`):
// the addresses of its bytes, and the frame until the queue takes it, or
// again once the queue lets it go before the lend ends, so that its bytes,
// which the segment being processed borrows, outlive that processing.
struct Lend {
    bytes: core::ops::Range<usize>,
    frame: Option<RxFrame>,
    taken: bool,
}

pub(crate) struct RxQueue {
    inorder: VecDeque<RxFrame>,
    ofo: BTreeMap<u64, OfoSeg>,
    // Start -> end of each maximal run of held out-of-order bytes.
    runs: BTreeMap<u64, u64>,
    anchors: BTreeSet<u64>,
    // The sequence and stream offset of the first unread byte.
    read_base: Seq,
    read: u64,
    readable: usize,
    ofo_bytes: usize,
    pushed: bool,
    deferred_syn: Option<DeferredSyn>,
    fin_sequence: Option<Seq>,
    eof: bool,
    latest: Option<Seq>,
    reported: [Option<Seq>; 4],
    report_debt: usize,
    pending_first: Option<Seq>,
    dsack: Option<(Seq, Seq)>,
    // Running sums over held frames: their truesize, and how many.
    frames: usize,
    entries: usize,
    lend: Option<Lend>,
}

impl core::fmt::Debug for RxQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxQueue")
            .field("read_base", &self.read_base)
            .field("readable", &self.readable)
            .field("ofo_bytes", &self.ofo_bytes)
            .field("eof", &self.eof)
            .finish_non_exhaustive()
    }
}

impl RxQueue {
    pub(crate) fn new(start: Seq) -> Self {
        Self {
            inorder: VecDeque::new(),
            ofo: BTreeMap::new(),
            runs: BTreeMap::new(),
            anchors: BTreeSet::new(),
            read_base: start,
            read: 0,
            readable: 0,
            ofo_bytes: 0,
            pushed: false,
            deferred_syn: None,
            fin_sequence: None,
            eof: false,
            latest: None,
            reported: [None; 4],
            report_debt: 0,
            pending_first: None,
            dsack: None,
            frames: 0,
            entries: 0,
            lend: None,
        }
    }

    // Lends `frame`, the received segment whose payload the next insertions
    // borrow: the part one of them holds is taken from it, trimmed, in
    // place of a copy. Until `end_lend`, the queue drops no frame it took
    // from it.
    pub(crate) fn lend(&mut self, frame: RxFrame) {
        debug_assert!(self.lend.is_none());
        let start = frame.as_ptr() as usize;
        self.lend = Some(Lend {
            bytes: start..start + frame.len(),
            frame: Some(frame),
            taken: false,
        });
    }

    // Ends the lend: the frame if the queue did not take it or has let it
    // go since, which its lender drops once the segment is processed.
    pub(crate) fn end_lend(&mut self) -> Option<RxFrame> {
        self.lend.take().and_then(|lend| lend.frame)
    }

    // The frame holding bytes `from..to` of `payload`.
    fn payload_frame(
        &mut self,
        payload: RxPayload<'_>,
        from: usize,
        to: usize,
    ) -> Result<RxFrame, ()> {
        match payload {
            RxPayload::Borrowed(bytes) => self.frame_of(&bytes[from..to]),
            owned => owned.into_frame(from, to),
        }
    }

    // The frame holding `bytes`, part of the payload being inserted: the
    // lent frame trimmed to them, or else a heap copy, whose allocation may
    // be refused.
    pub(crate) fn frame_of(&mut self, bytes: &[u8]) -> Result<RxFrame, ()> {
        let at = bytes.as_ptr() as usize;
        if let Some(lend) = &mut self.lend
            && !lend.taken
            && lend.bytes.start <= at
            && at + bytes.len() <= lend.bytes.end
        {
            let mut frame = lend.frame.take().unwrap();
            lend.taken = true;
            let offset = at - lend.bytes.start;
            frame.truncate(offset + bytes.len());
            frame.advance(offset);
            return Ok(frame);
        }
        heap_copy(bytes)
    }

    // Drops a frame the queue no longer holds, except the lent one, which
    // goes back to the lend.
    fn discard(&mut self, frame: RxFrame) {
        if let Some(lend) = &mut self.lend
            && lend.taken
            && lend.bytes.contains(&(frame.as_ptr() as usize))
        {
            lend.frame = Some(frame);
        } else {
            drop(frame);
        }
    }

    // Linux's sk_rmem_alloc: every held frame's truesize plus
    // RX_ENTRY_TRUESIZE.
    pub(crate) fn rmem(&self) -> usize {
        self.frames + self.entries * RX_ENTRY_TRUESIZE
    }

    // The heap the queue holds, as the memory budget charges it: the
    // frames, the in-order deque's slots and the maps' nodes (a bound
    // the counting-allocator test checks).
    pub(crate) fn storage(&self) -> usize {
        self.frames
            + self.inorder.capacity() * size_of::<RxFrame>()
            + map_bytes(self.ofo.len(), OFO_PAIR)
            + map_bytes(self.runs.len(), RUN_PAIR)
            + map_bytes(self.anchors.len(), ANCHOR_PAIR)
    }

    fn hold(&mut self, frame: &RxFrame) {
        self.frames += frame.truesize();
        self.entries += 1;
    }

    fn release(&mut self, frame: RxFrame) {
        self.frames -= frame.truesize();
        self.entries -= 1;
        self.discard(frame);
    }

    // std's BTreeMap keeps its root leaf after its last entry is removed:
    // an emptied map gives it back, so an idle queue holds no storage.
    fn shed(&mut self) {
        if self.ofo.is_empty() {
            self.ofo = BTreeMap::new();
        }
        if self.runs.is_empty() {
            self.runs = BTreeMap::new();
        }
        if self.anchors.is_empty() {
            self.anchors = BTreeSet::new();
        }
    }

    fn seq(&self, offset: u64) -> Seq {
        self.read_base.wrapping_add((offset - self.read) as u32)
    }

    // The stream offset of `seq`, if it is not before the read point.
    fn offset(&self, seq: Seq) -> Option<u64> {
        let distance = seq.distance_from(self.read_base);
        (distance < 1 << 31).then(|| self.read + u64::from(distance))
    }

    // The out-of-order run holding byte `offset`.
    fn run_at(&self, offset: u64) -> Option<(u64, u64)> {
        self.runs
            .range(..=offset)
            .next_back()
            .filter(|&(_, &end)| end > offset)
            .map(|(&start, &end)| (start, end))
    }

    // The first out-of-order run that ends after `offset`.
    fn run_from(&self, offset: u64) -> Option<(u64, u64)> {
        self.run_at(offset)
            .or_else(|| self.runs.range(offset..).next().map(|(&s, &e)| (s, e)))
    }

    // Only the initial SYN prefix can be staged. No presence/reporting
    // state is published until validated establishment; next() remains
    // IRS+1 throughout. The deque slot promotion needs is taken now, so
    // that establishment never allocates; a refusal stages nothing, and
    // lets the frame go (`discard`: a lent one goes back to the lend).
    pub(crate) fn defer_syn(&mut self, frame: RxFrame, fin: bool, push: bool) -> Result<(), ()> {
        assert!(!self.has_data() && self.fin_sequence.is_none() && self.deferred_syn.is_none());
        let len = frame.len();
        if len != 0 && self.inorder.try_reserve(1).is_err() {
            self.discard(frame);
            return Err(());
        }
        let frame = (len != 0).then_some(frame);
        if let Some(frame) = &frame {
            self.hold(frame);
        }
        self.deferred_syn = Some((frame, len, fin, push));
        Ok(())
    }

    pub(crate) fn promote_syn(&mut self) -> Option<usize> {
        let (frame, count, fin, push) = self.deferred_syn.take()?;
        if let Some(frame) = frame {
            self.inorder.push_back(frame);
        }
        self.readable = count;
        self.pushed = push && count != 0;
        if fin {
            self.fin_sequence = Some(self.next());
            self.eof = true;
        }
        Some(count)
    }

    pub(crate) fn clear(&mut self) {
        if self.lend.as_ref().is_some_and(|lend| lend.taken) {
            let inorder = core::mem::take(&mut self.inorder);
            let ofo = core::mem::take(&mut self.ofo);
            let syn = self.deferred_syn.take().and_then(|syn| syn.0);
            for frame in inorder
                .into_iter()
                .chain(ofo.into_values().map(|seg| seg.frame))
                .chain(syn)
            {
                self.discard(frame);
            }
        }
        self.inorder = VecDeque::new();
        self.ofo = BTreeMap::new();
        self.runs = BTreeMap::new();
        self.anchors = BTreeSet::new();
        self.read_base = Seq(0);
        self.read = 0;
        self.readable = 0;
        self.ofo_bytes = 0;
        self.pushed = false;
        self.deferred_syn = None;
        self.fin_sequence = None;
        self.eof = false;
        self.latest = None;
        self.reported = [None; 4];
        self.report_debt = 0;
        self.pending_first = None;
        self.dsack = None;
        self.frames = 0;
        self.entries = 0;
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
            .wrapping_add(self.readable as u32)
            .wrapping_add(u32::from(self.eof))
    }

    pub(crate) fn readable(&self) -> usize {
        self.readable
    }

    // The sequence after the last byte held beyond a gap, if any: the end
    // of Linux's out-of-order queue (ooo_last_skb).
    pub(crate) fn out_of_order_end(&self) -> Option<Seq> {
        let (_, &end) = self.runs.last_key_value()?;
        Some(self.seq(end))
    }

    pub(crate) fn occupied(&self) -> usize {
        self.readable + self.ofo_bytes
    }

    pub(crate) fn has_data(&self) -> bool {
        self.occupied() != 0 || self.deferred_syn.as_ref().is_some_and(|syn| syn.1 != 0)
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
        let frontier = self.read_base.wrapping_add(self.readable as u32);
        let distance = sequence.distance_from(frontier);
        if distance == 1 << 31 {
            return;
        }
        let start = distance as i32 as i64;
        if start < 0 {
            self.dsack = Some((
                sequence,
                sequence.wrapping_add(payload_len.min((-start) as usize) as u32),
            ));
            return;
        }
        // Nothing is held beyond a gap, so data at or above the frontier
        // duplicates nothing: as Linux tcp_data_queue sets a D-SACK only
        // below rcv_nxt or over its out-of-order queue.
        if self.runs.is_empty() {
            return;
        }
        let edge = self.read + self.readable as u64;
        let from = edge + start as u64;
        if let Some((left, right)) = self.run_from(from) {
            let (left, right) = (left.max(from), right.min(from + payload_len as u64));
            if left < right {
                self.dsack = Some((self.seq(left), self.seq(right)));
            }
        }
    }

    pub(crate) fn clear_dsack(&mut self) {
        self.dsack = None;
    }

    // Whether the next SACK-bearing output reports a duplicate.
    pub(crate) fn dsack_pending(&self) -> bool {
        self.dsack.is_some()
    }

    // Whether sack_blocks reports any block: a pending duplicate, or data
    // held beyond a gap, as Linux tests its out-of-order queue for
    // emptiness.
    pub(crate) fn has_sack_blocks(&self) -> bool {
        self.dsack.is_some() || !self.runs.is_empty()
    }

    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Ordinary SACK selects newest contiguous retained union first, except arrivals advancing the cumulative frontier. RFC 2883 DSACK is a separate first-block extension, not asserted as ordinary RFC 2018 behavior.
    //# * The first SACK block (i.e., the one immediately following the kind and
    //# length fields in the option) MUST specify the contiguous block of data
    //# containing the segment which triggered this ACK, unless that segment
    //# advanced the Acknowledgment Number field in the header.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-4
    //= reason=Four successful first-block anchors provide report history; anchors resolve through the out-of-order runs after merges and cumulative advancement. Encoding failure does not change history.
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
        if !self.has_sack_blocks() || limit == 0 {
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
        // Fill unused wire slots with actual held runs, not arrival history.
        for (&left, &right) in &self.runs {
            if count == limit {
                break;
            }
            let block = Some((self.seq(left).0, self.seq(right).0));
            if !blocks[..count].contains(&block) {
                blocks[count] = block;
                count += 1;
            }
        }
        blocks
    }

    pub(crate) fn output_undo(&self) -> RxOutputUndo {
        RxOutputUndo {
            reported: self.reported,
            dsack: self.dsack,
            report_debt: self.report_debt,
            pending_first: self.pending_first,
            anchor: self
                .report_anchor()
                .filter(|&seq| self.pending(seq))
                .and_then(|seq| self.offset(seq)),
        }
    }

    // Output consumes at most one pending anchor. Reservation ownership
    // excludes input/read mutation, so restoring it and the fixed report
    // metadata is exact. Whether an anchor was put back (storage may have
    // changed).
    pub(crate) fn restore_output(&mut self, undo: RxOutputUndo) -> bool {
        self.reported = undo.reported;
        self.dsack = undo.dsack;
        self.report_debt = undo.report_debt;
        self.pending_first = undo.pending_first;
        undo.anchor
            .is_some_and(|anchor| self.anchors.insert(anchor))
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
        self.offset(seq)
            .is_some_and(|offset| self.anchors.contains(&offset))
    }

    fn report_anchor(&self) -> Option<Seq> {
        if let Some(latest) = self.latest
            && self.pending(latest)
        {
            return Some(latest);
        }
        self.pending_first.or(self.latest)
    }

    // Whether an anchor was taken (storage may have changed).
    pub(crate) fn commit_report(&mut self) -> bool {
        self.report_debt = self.report_debt.saturating_sub(1);
        let Some(anchor) = self.report_anchor() else {
            return false;
        };
        let Some(offset) = self.offset(anchor) else {
            return false;
        };
        if !self.anchors.remove(&offset) {
            return false;
        }
        if self.pending_first == Some(anchor) {
            self.pending_first = self.find_pending(offset + 1);
        }
        self.shed();
        true
    }

    // The first anchor at or after `offset`, while anything is held and a
    // report is owed.
    fn find_pending(&self, offset: u64) -> Option<Seq> {
        if self.occupied() == 0 || self.report_debt == 0 {
            return None;
        }
        let &anchor = self.anchors.range(offset..).next()?;
        Some(self.seq(anchor))
    }

    fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)> {
        let (left, right) = self.run_at(self.offset(seq)?)?;
        Some((self.seq(left), self.seq(right)))
    }

    // Copies frames from the front of the in-order data into `out`; the
    // count copied.
    fn copy_front(&self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.readable);
        let mut copied = 0;
        for frame in &self.inorder {
            if copied == count {
                break;
            }
            let len = frame.len().min(count - copied);
            out[copied..copied + len].copy_from_slice(&frame[..len]);
            copied += len;
        }
        count
    }

    pub(crate) fn peek(&self, out: &mut [u8]) -> usize {
        self.copy_front(out)
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let count = self.copy_front(out);
        if count == 0 {
            return 0;
        }
        // Each frame read to its end is released (Linux
        // tcp_eat_recv_skb); a partly read one keeps its whole charge.
        let mut left = count;
        while left != 0 {
            let front = self.inorder.front_mut().unwrap();
            if front.len() > left {
                front.advance(left);
                break;
            }
            left -= front.len();
            let frame = self.inorder.pop_front().unwrap();
            self.release(frame);
        }
        if self.inorder.is_empty() {
            self.inorder = VecDeque::new();
        }
        self.readable -= count;
        self.read += count as u64;
        self.read_base = self.read_base.wrapping_add(count as u32);
        // Anchors survive in the in-order data only after out-of-order
        // input.
        while let Some(&anchor) = self.anchors.first()
            && anchor < self.read
        {
            self.anchors.pop_first();
        }
        self.shed();
        if self
            .pending_first
            .is_some_and(|seq| seq.distance_from(self.read_base) >= 1 << 31)
        {
            self.pending_first = self.find_pending(self.read);
        }
        count
    }

    // Takes the run that starts at the in-order edge, if any, into the
    // in-order data, with its PUSH marks.
    fn promote(&mut self) {
        let edge = self.read + self.readable as u64;
        let Some((&start, &end)) = self.runs.first_key_value() else {
            return;
        };
        if start != edge {
            return;
        }
        self.runs.pop_first();
        while let Some(entry) = self.ofo.first_entry()
            && *entry.key() < end
        {
            let seg = entry.remove();
            self.pushed |= seg.push;
            self.inorder.push_back(seg.frame);
        }
        let len = (end - start) as usize;
        self.readable += len;
        self.ofo_bytes -= len;
    }

    // The new bytes of stream bytes [from, to): from the first one no run
    // holds to the end of the last, if any.
    fn new_span(&self, from: u64, to: u64) -> Option<(u64, u64)> {
        let first = self.run_at(from).map_or(from, |(_, end)| end);
        if first >= to {
            return None;
        }
        let last = self.run_at(to - 1).map_or(to, |(start, _)| start);
        Some((first, last))
    }

    // A heap frame of `span`, the arrival's bytes from stream offset
    // `from`, over which the entries it covers are copied: as Linux's
    // tcp_data_queue_ofo (merge_right) one entry replaces those a new
    // arrival covers, and a byte held twice keeps its first copy, as
    // RFC 9293 processes only the new parts of a segment, so that the bytes
    // read are those whose arrival the receive metadata (RX timestamps)
    // records. A rare path: a retransmission covering held data.
    fn merged_frame(&self, span: &[u8], from: u64) -> Result<RxFrame, ()> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.try_reserve_exact(span.len()).map_err(|_| ())?;
        bytes.extend_from_slice(span);
        for (&start, seg) in self.ofo.range(from..from + span.len() as u64) {
            let at = (start - from) as usize;
            bytes[at..at + seg.frame.len()].copy_from_slice(&seg.frame);
        }
        Ok(RxFrame::from_vec(bytes))
    }

    // Holds `frame`, stream bytes [from, to), which start and end at gaps
    // beyond the in-order edge: every entry between them is replaced by the
    // new frame, which takes its PUSH mark (`merged_frame`).
    fn hold_run(&mut self, frame: RxFrame, from: u64, to: u64) {
        let mut push = false;
        while let Some((&start, _)) = self.ofo.range(from..to).next() {
            let seg = self.ofo.remove(&start).unwrap();
            push |= seg.push;
            self.release(seg.frame);
        }
        while let Some((&start, _)) = self.runs.range(from..to).next() {
            self.runs.remove(&start);
        }
        debug_assert_eq!(frame.len() as u64, to - from);
        self.hold(&frame);
        self.ofo.insert(from, OfoSeg { frame, push });
        let mut start = from;
        let mut end = to;
        if let Some((&left, &right)) = self.runs.range(..from).next_back()
            && right == from
        {
            start = left;
        }
        if let Some(right) = self.runs.remove(&to) {
            end = right;
        }
        self.runs.insert(start, end);
    }

    // Takes the part of `payload`, the stream from `sequence`, within the
    // right edge `limit` and not already held; the connection performs
    // state and segment acceptability checks. Accepted runs are relative to
    // the unread payload base, excluding duplicates and FIN.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //# Segments with higher beginning sequence numbers SHOULD be held for later processing
    //# (SHLD-31).
    pub(crate) fn insert(
        &mut self,
        sequence: Seq,
        payload: RxPayload<'_>,
        fin: bool,
        push: bool,
        limit: Seq,
        mut accepted: impl FnMut(usize, usize),
    ) -> ReceiveOutcome {
        let len = payload.len();
        let previous_next = self.next();
        let had_holes = !self.runs.is_empty();
        let mut outcome = ReceiveOutcome {
            new_bytes: 0,
            sack_overflow: false,
            advanced: false,
            fin: false,
            out_of_order: (len != 0 || fin) && sequence != previous_next,
            refused: false,
        };
        if self.eof || (len == 0 && !fin) {
            return outcome;
        }
        let capacity = limit.distance_from(self.read_base) as usize;
        debug_assert!(capacity < 1 << 31);
        let data_limit = self
            .fin_sequence
            .map_or(capacity, |end| end.distance_from(self.read_base) as usize);
        let contiguous = self.readable;
        // In-order text that fits, with nothing held beyond a gap: every
        // byte is new and extends the in-order data, with no reporting
        // anchor and PUSH taken at once. A FIN on it follows every held
        // byte, so it is kept when it lies within the limit and none is
        // kept yet, as below. Its frame and deque slot are taken first: a
        // refusal leaves the queue as it was.
        if len != 0 && !outcome.out_of_order && !had_holes && contiguous + len <= data_limit {
            let Ok(frame) = self.payload_frame(payload, 0, len) else {
                outcome.refused = true;
                return outcome;
            };
            if self.inorder.try_reserve(1).is_err() {
                self.discard(frame);
                outcome.refused = true;
                return outcome;
            }
            self.hold(&frame);
            self.inorder.push_back(frame);
            let end = contiguous + len;
            accepted(contiguous, end);
            outcome.new_bytes = len;
            self.readable = end;
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
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //# If a segment's contents straddle the boundary between old and new, only the
        //# new parts are processed.
        // The payload's bytes within [in-order edge, data_limit), as
        // offsets from the read point; `skew` maps them back into it.
        let start = u64::from(sequence.distance_from(self.read_base));
        let (lo, hi, skew) = if start < 1 << 31 {
            (start, (start + len as u64).min(data_limit as u64), start)
        } else {
            let wrapped = (start + len as u64).saturating_sub(1 << 32);
            (
                0,
                wrapped.min(data_limit as u64),
                start.wrapping_sub(1 << 32),
            )
        };
        let lo = lo.max(contiguous as u64);
        // The frame holding the new bytes, and the deque slots a promotion
        // they cause needs, are taken before anything changes: a refusal
        // leaves the queue as it was. BTreeMap nodes are allocated
        // infallibly (n0bw D8).
        let span = if lo < hi {
            self.new_span(self.read + lo, self.read + hi)
        } else {
            None
        };
        let mut frame = None;
        if let Some((from, to)) = span {
            let skip = (from - self.read).wrapping_sub(skew) as usize;
            let edge = self.read + contiguous as u64;
            let promoted = if from == edge {
                let end = self.runs.get(&to).copied().unwrap_or(to);
                1 + self.ofo.range(to..end).count()
            } else {
                0
            };
            let len = (to - from) as usize;
            let built = if self.ofo.range(from..to).next().is_some() {
                self.merged_frame(&payload.bytes()[skip..skip + len], from)
            } else {
                self.payload_frame(payload, skip, skip + len)
            };
            match built {
                Ok(held) if self.inorder.try_reserve(promoted).is_ok() => frame = Some(held),
                built => {
                    if let Ok(held) = built {
                        self.discard(held);
                    }
                    outcome.refused = true;
                    return outcome;
                }
            }
        }
        let mut new_anchor = None;
        // The first and past the last new byte, as stream offsets.
        let mut stored: Option<(u64, u64)> = None;
        if lo < hi {
            let read = self.read;
            let (from, to) = (read + lo, read + hi);
            let mut at = from;
            let mut gap = |start: u64, end: u64, accepted: &mut dyn FnMut(usize, usize)| {
                if start < end {
                    accepted((start - read) as usize, (end - read) as usize);
                    outcome.new_bytes += (end - start) as usize;
                    let span = stored.get_or_insert((start, end));
                    span.1 = end;
                }
            };
            if let Some((_, end)) = self.run_at(from) {
                at = end;
            }
            for (&left, &right) in self.runs.range(from..to) {
                gap(at, left, &mut accepted);
                at = right;
            }
            gap(at, to, &mut accepted);
        }
        debug_assert_eq!(stored, span);
        if let (Some((from, to)), Some(frame)) = (stored, frame) {
            new_anchor = Some(self.seq(from));
            self.hold_run(frame, from, to);
            self.ofo_bytes += outcome.new_bytes;
        }

        if let Some(anchor) = new_anchor
            && (outcome.out_of_order || had_holes)
        {
            let offset = stored.unwrap().0;
            self.anchors.insert(offset);
            if self.pending_first.is_none_or(|old| {
                anchor.distance_from(self.read_base) < old.distance_from(self.read_base)
            }) {
                self.pending_first = Some(anchor);
            }
            // ponytail: after application reads, cumulative-only ACK debt is
            // coalesced at capacity under prolonged output exhaustion. Retained
            // fragments keep individual anchors; use driver backpressure if
            // every already-consumed arrival must retain a separate ACK.
            self.report_debt = self.report_debt.saturating_add(1).min(capacity);
        }
        if push && len != 0 {
            let last = sequence.wrapping_add(len as u32 - 1);
            let distance = last.distance_from(self.read_base) as usize;
            // A duplicate may introduce PSH on buffered out-of-order text, but
            // never re-notify a mark already passed by the in-order edge.
            if distance >= contiguous && distance < data_limit {
                let offset = self.read + distance as u64;
                if let Some((&start, seg)) = self.ofo.range_mut(..=offset).next_back()
                    && start + seg.frame.len() as u64 > offset
                {
                    seg.push = true;
                }
            }
        }

        if fin && self.fin_sequence.is_none() {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
            //# while the FIN is considered to occur after the last actual data octet in a
            //# segment in which it occurs.
            let end = sequence.wrapping_add(len as u32);
            let distance = end.distance_from(self.read_base) as usize;
            // Reject a FIN before held text.
            let held = self
                .runs
                .last_key_value()
                .map_or(self.readable as u64, |(_, &end)| end - self.read);
            if distance < capacity && held <= distance as u64 {
                self.fin_sequence = Some(end);
            }
        }
        // The in-order data extends over the run at its edge, taking its
        // PUSH marks.
        self.promote();
        self.shed();
        // This queue consumes FIN once after preceding data; SYN processing
        // is in the connection.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //# one and only one copy of the control will be acted upon
        if self.fin_sequence == Some(self.next()) {
            self.eof = true;
            outcome.fin = true;
        }
        outcome.advanced = self.next() != previous_next;
        self.latest = None;
        if !outcome.advanced && len != 0 {
            let offset = u64::from(sequence.distance_from(self.read_base));
            let from = offset.max(self.readable as u64);
            if from < capacity as u64
                && let Some((left, _)) = self.run_from(self.read + from)
            {
                let left = (left - self.read).max(from);
                if left < data_limit as u64 && left < offset + len as u64 {
                    self.latest = new_anchor.or(Some(self.read_base.wrapping_add(left as u32)));
                }
            }
        }
        outcome
    }
}

#[cfg(debug_assertions)]
impl RxQueue {
    // A full recount of every running total and structural invariant:
    // entries apart and in order, runs the maximal unions of the entries
    // beyond a gap, anchors on held bytes. Linear: debug builds only.
    pub(crate) fn debug_check(&self) {
        let (mut frames, mut entries) = (0, 0);
        let mut readable = 0;
        for frame in &self.inorder {
            assert!(!frame.is_empty());
            frames += frame.truesize();
            entries += 1;
            readable += frame.len();
        }
        if let Some((Some(frame), ..)) = &self.deferred_syn {
            frames += frame.truesize();
            entries += 1;
        }
        assert_eq!(readable, self.readable);
        let edge = self.read + readable as u64;
        let mut runs = alloc::vec::Vec::<(u64, u64)>::new();
        let mut ofo_bytes = 0;
        for (&start, seg) in &self.ofo {
            assert!(!seg.frame.is_empty());
            frames += seg.frame.truesize();
            entries += 1;
            ofo_bytes += seg.frame.len();
            let end = start + seg.frame.len() as u64;
            match runs.last_mut() {
                Some(run) if run.1 == start => run.1 = end,
                Some(run) => {
                    assert!(run.1 < start);
                    runs.push((start, end));
                }
                None => {
                    assert!(start > edge);
                    runs.push((start, end));
                }
            }
        }
        assert_eq!(ofo_bytes, self.ofo_bytes);
        assert!(
            runs.iter()
                .copied()
                .eq(self.runs.iter().map(|(&s, &e)| (s, e)))
        );
        assert_eq!((frames, entries), (self.frames, self.entries));
        assert_eq!(self.rmem(), frames + entries * RX_ENTRY_TRUESIZE);
        let held = runs.last().map_or(edge, |run| run.1);
        for &anchor in &self.anchors {
            assert!(anchor >= self.read && anchor < held);
            assert!(anchor < edge || self.run_at(anchor).is_some());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        allocation_tests::counting,
        buffer::receive_differential::{ReceiveQueue, Snapshot, assert_covered, heap_frame, run},
    };
    use alloc::vec::Vec;

    impl ReceiveQueue for RxQueue {
        type Undo = RxOutputUndo;
        fn create(start: Seq, _capacity: usize) -> Self {
            Self::new(start)
        }
        fn defer_syn(&mut self, frame: RxFrame, fin: bool, push: bool) {
            RxQueue::defer_syn(self, frame, fin, push).unwrap()
        }
        fn promote_syn(&mut self) -> Option<usize> {
            RxQueue::promote_syn(self)
        }
        // A frame without spare capacity goes in borrowed, copied for the
        // part kept, as the copying input path does.
        fn insert(
            &mut self,
            sequence: Seq,
            frame: RxFrame,
            fin: bool,
            push: bool,
            limit: Seq,
            accepted: &mut dyn FnMut(usize, usize),
        ) -> ReceiveOutcome {
            if frame.truesize() == frame.len() {
                RxQueue::insert(
                    self,
                    sequence,
                    RxPayload::Borrowed(&frame),
                    fin,
                    push,
                    limit,
                    accepted,
                )
            } else {
                RxQueue::insert(
                    self,
                    sequence,
                    RxPayload::Owned(frame),
                    fin,
                    push,
                    limit,
                    accepted,
                )
            }
        }
        fn record_duplicate(&mut self, sequence: Seq, len: usize) {
            RxQueue::record_duplicate(self, sequence, len)
        }
        fn read(&mut self, out: &mut [u8]) -> usize {
            RxQueue::read(self, out)
        }
        fn peek(&self, out: &mut [u8]) -> usize {
            RxQueue::peek(self, out)
        }
        fn sack_blocks(&self, max_blocks: usize) -> [Option<(u32, u32)>; 4] {
            RxQueue::sack_blocks(self, max_blocks)
        }
        fn output_undo(&self) -> RxOutputUndo {
            RxQueue::output_undo(self)
        }
        fn commit_sack(&mut self, first: (u32, u32)) {
            RxQueue::commit_sack(self, first)
        }
        fn commit_report(&mut self) {
            RxQueue::commit_report(self);
        }
        fn restore_output(&mut self, undo: RxOutputUndo) {
            RxQueue::restore_output(self, undo);
        }
        fn take_push(&mut self) -> bool {
            RxQueue::take_push(self)
        }
        fn clear(&mut self) {
            RxQueue::clear(self)
        }
        fn reset_start(&mut self, start: Seq) -> Result<(), ()> {
            RxQueue::reset_start(self, start)
        }
        fn clear_dsack(&mut self) {
            RxQueue::clear_dsack(self)
        }
        fn grow(&mut self, _capacity: usize) -> Result<(), ()> {
            Ok(())
        }
        fn snapshot(&self) -> Snapshot {
            Snapshot {
                next: self.next(),
                readable: self.readable(),
                eof: self.eof(),
                has_data: self.has_data(),
                out_of_order_end: self.out_of_order_end(),
                has_sack_blocks: self.has_sack_blocks(),
                dsack_pending: self.dsack_pending(),
                has_pending_report: self.has_pending_report(),
                read_base: self.read_base,
                occupied: self.occupied(),
                fin_sequence: self.fin_sequence,
                latest: self.latest,
                reported: self.reported,
                report_debt: self.report_debt,
                pending_first: self.pending_first,
                dsack: self.dsack,
                pushed: self.pushed,
                deferred_syn: self
                    .deferred_syn
                    .as_ref()
                    .map(|(_, len, fin, push)| (*len, *fin, *push)),
            }
        }
        fn byte_at(&self, seq: Seq) -> Option<u8> {
            let offset = self.offset(seq)?;
            let mut at = self.read;
            for frame in &self.inorder {
                if offset < at + frame.len() as u64 {
                    return Some(frame[(offset - at) as usize]);
                }
                at += frame.len() as u64;
            }
            let (&start, seg) = self.ofo.range(..=offset).next_back()?;
            seg.frame.get((offset - start) as usize).copied()
        }
        fn pending(&self, seq: Seq) -> bool {
            RxQueue::pending(self, seq)
        }
        fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)> {
            RxQueue::block_at(self, seq)
        }
        fn runs(&self) -> Vec<(Seq, Seq, bool)> {
            self.runs
                .iter()
                .map(|(&start, &end)| {
                    let push = self.ofo.range(start..end).any(|(_, seg)| seg.push);
                    (self.seq(start), self.seq(end), push)
                })
                .collect()
        }
        fn check(&self) {
            self.debug_check();
        }
    }

    #[test]
    fn rx_queue_matches_the_per_byte_reference() {
        let coverage = run::<RxQueue>(200, 120, 0x7f4a_7c15);
        assert_eq!(coverage.steps, 24_000);
        assert_covered(&coverage);
    }

    // Soak: run once per commit in a release build with debug assertions
    // (`--profile packetdrill`).
    #[test]
    #[ignore]
    fn rx_queue_matches_the_per_byte_reference_soak() {
        let coverage = run::<RxQueue>(2000, 120, 0x2545_f491);
        extern crate std;
        std::eprintln!("{coverage:?}");
    }

    // An RxQueue whose every mutation runs under the counting allocator:
    // `live` is the heap it holds (frames are reallocated inside the count),
    // which must stay within what it charges.
    struct Counted {
        queue: RxQueue,
        live: isize,
    }

    impl Counted {
        fn with<T>(&mut self, call: impl FnOnce(&mut RxQueue) -> T) -> T {
            let queue = &mut self.queue;
            counting(&mut self.live, || call(queue))
        }
        // `frame` reallocated inside the count.
        fn adopt(&mut self, frame: RxFrame) -> RxFrame {
            let spare = frame.truesize() - frame.len();
            counting(&mut self.live, || heap_frame(&frame, spare))
        }
    }

    impl ReceiveQueue for Counted {
        type Undo = RxOutputUndo;
        fn create(start: Seq, capacity: usize) -> Self {
            let mut live = 0;
            let queue = counting(&mut live, || {
                <RxQueue as ReceiveQueue>::create(start, capacity)
            });
            Self { queue, live }
        }
        fn defer_syn(&mut self, frame: RxFrame, fin: bool, push: bool) {
            let frame = self.adopt(frame);
            self.with(|q| q.defer_syn(frame, fin, push)).unwrap()
        }
        fn promote_syn(&mut self) -> Option<usize> {
            self.with(|q| q.promote_syn())
        }
        fn insert(
            &mut self,
            sequence: Seq,
            frame: RxFrame,
            fin: bool,
            push: bool,
            limit: Seq,
            accepted: &mut dyn FnMut(usize, usize),
        ) -> ReceiveOutcome {
            let frame = self.adopt(frame);
            // A frame the queue copies from is freed outside the count, and
            // the accepted runs are recorded into storage reserved outside it.
            let borrowed = frame.truesize() == frame.len();
            let mut kept = None;
            let mut runs = Vec::with_capacity(frame.len() + 1);
            let record = &mut |start, end| runs.push((start, end));
            let outcome = self.with(|q| {
                if borrowed {
                    let outcome = RxQueue::insert(
                        q,
                        sequence,
                        RxPayload::Borrowed(&frame),
                        fin,
                        push,
                        limit,
                        record,
                    );
                    kept = Some(frame);
                    outcome
                } else {
                    RxQueue::insert(
                        q,
                        sequence,
                        RxPayload::Owned(frame),
                        fin,
                        push,
                        limit,
                        record,
                    )
                }
            });
            for (start, end) in runs {
                accepted(start, end);
            }
            if let Some(frame) = kept {
                self.live -= frame.truesize() as isize;
            }
            outcome
        }
        fn record_duplicate(&mut self, sequence: Seq, len: usize) {
            self.with(|q| q.record_duplicate(sequence, len))
        }
        fn read(&mut self, out: &mut [u8]) -> usize {
            self.with(|q| q.read(out))
        }
        fn peek(&self, out: &mut [u8]) -> usize {
            self.queue.peek(out)
        }
        fn sack_blocks(&self, max_blocks: usize) -> [Option<(u32, u32)>; 4] {
            self.queue.sack_blocks(max_blocks)
        }
        fn output_undo(&self) -> RxOutputUndo {
            self.queue.output_undo()
        }
        fn commit_sack(&mut self, first: (u32, u32)) {
            self.with(|q| q.commit_sack(first))
        }
        fn commit_report(&mut self) {
            self.with(|q| q.commit_report());
        }
        fn restore_output(&mut self, undo: RxOutputUndo) {
            self.with(|q| q.restore_output(undo));
        }
        fn take_push(&mut self) -> bool {
            self.queue.take_push()
        }
        fn clear(&mut self) {
            self.with(|q| q.clear())
        }
        fn reset_start(&mut self, start: Seq) -> Result<(), ()> {
            self.queue.reset_start(start)
        }
        fn clear_dsack(&mut self) {
            self.queue.clear_dsack()
        }
        fn grow(&mut self, _capacity: usize) -> Result<(), ()> {
            Ok(())
        }
        fn snapshot(&self) -> Snapshot {
            ReceiveQueue::snapshot(&self.queue)
        }
        fn byte_at(&self, seq: Seq) -> Option<u8> {
            ReceiveQueue::byte_at(&self.queue, seq)
        }
        fn pending(&self, seq: Seq) -> bool {
            self.queue.pending(seq)
        }
        fn block_at(&self, seq: Seq) -> Option<(Seq, Seq)> {
            self.queue.block_at(seq)
        }
        fn runs(&self) -> Vec<(Seq, Seq, bool)> {
            ReceiveQueue::runs(&self.queue)
        }
        fn check(&self) {
            let queue = &self.queue;
            queue.debug_check();
            let live = usize::try_from(self.live).unwrap();
            // Frames are allocated at their truesize, the deque at its
            // capacity: the maps' share is what is left, within its bound.
            assert!(
                live >= queue.frames + queue.inorder.capacity() * size_of::<RxFrame>(),
                "{live}"
            );
            assert!(live <= queue.storage(), "{live} > {}", queue.storage());
        }
    }

    #[test]
    fn heap_held_stays_within_the_charged_storage() {
        let coverage = run::<Counted>(60, 120, 0x51ed_270b);
        assert_eq!(coverage.steps, 7_200);
    }

    // A hostile peer's 1-byte segments, one in every other position, in
    // order, in reverse and interleaved: the queue's heap stays within its
    // charge at every size, and drains to nothing.
    #[test]
    fn one_byte_out_of_order_segments_stay_within_the_charge() {
        let start = Seq(u32::MAX - 3000);
        let mut queue = Counted::create(start, 0);
        let limit = start.wrapping_add(1 << 20);
        let insert = |queue: &mut Counted, offset: u32| {
            let byte = [offset as u8];
            let outcome = queue.insert(
                start.wrapping_add(offset),
                heap_frame(&byte, 0),
                false,
                false,
                limit,
                &mut |_, _| {},
            );
            // The recount is linear: every 64th insertion.
            if offset % 128 < 2 {
                queue.check();
            }
            outcome.new_bytes
        };
        let mut held = 0;
        for i in 0..3000 {
            held += insert(&mut queue, 1 + 2 * i);
        }
        for i in (3000..6000).rev() {
            held += insert(&mut queue, 1 + 2 * i);
        }
        for i in (6000..9000).step_by(3) {
            for k in [2, 0, 1] {
                held += insert(&mut queue, 1 + 2 * (i + k));
            }
        }
        assert_eq!(held, 9000);
        assert_eq!(queue.queue.ofo.len(), 9000);
        assert_eq!(queue.queue.rmem(), 9000 * (1 + RX_ENTRY_TRUESIZE));
        // Filling the gaps promotes everything.
        for i in 0..=9000 {
            insert(&mut queue, 2 * i);
        }
        assert_eq!(queue.queue.readable(), 18_001);
        assert!(queue.queue.ofo.is_empty() && queue.queue.runs.is_empty());
        let mut out = alloc::vec![0; 18_001];
        assert_eq!(queue.read(&mut out), 18_001);
        queue.check();
        assert_eq!(
            (queue.queue.storage(), queue.queue.rmem(), queue.live),
            (0, 0, 0)
        );
    }

    // Each frame stays charged its whole truesize until its last byte is
    // read; an empty queue holds nothing.
    #[test]
    fn frames_are_released_when_read_to_their_end() {
        let start = Seq(1000);
        let limit = start.wrapping_add(65536);
        let mut queue = RxQueue::new(start);
        assert_eq!((queue.storage(), queue.rmem()), (0, 0));
        let frame = heap_frame(&[7; 100], 2204);
        let outcome = queue.insert(
            start,
            RxPayload::Owned(frame),
            false,
            true,
            limit,
            |_, _| {},
        );
        assert_eq!(outcome.new_bytes, 100);
        let deque = queue.inorder.capacity() * size_of::<RxFrame>();
        assert_eq!(queue.storage(), 2304 + deque);
        assert_eq!(queue.rmem(), 2304 + RX_ENTRY_TRUESIZE);
        // A borrowed payload is copied at its length.
        queue.insert(
            start.wrapping_add(100),
            RxPayload::Borrowed(&[8; 50]),
            false,
            false,
            limit,
            |_, _| {},
        );
        assert_eq!(queue.storage(), 2354 + deque);
        let mut out = [0; 99];
        assert_eq!(queue.read(&mut out), 99);
        assert_eq!(
            queue.storage(),
            2354 + deque,
            "a partly read frame keeps its charge"
        );
        assert_eq!(queue.read(&mut out[..1]), 1);
        assert_eq!(queue.storage(), 50 + deque);
        assert_eq!(queue.read(&mut out), 50);
        assert_eq!(
            (queue.storage(), queue.rmem(), queue.inorder.capacity()),
            (0, 0, 0)
        );
        assert!(queue.take_push());
    }

    // Overlapping arrivals with different bytes: a frame covering held
    // entries replaces them with one entry (Linux tcp_data_queue_ofo's
    // merge_right), whose held bytes keep their first copy, as the per-byte
    // ring kept them; a frame inside one entry, or the parts of one that
    // overlap its neighbours, are dropped. A covering frame owned by the
    // queue is copied into a heap frame of the span.
    #[test]
    fn a_frame_covering_held_entries_replaces_them_keeping_their_bytes() {
        let start = Seq(0);
        let limit = Seq(1000);
        let mut queue = RxQueue::new(start);
        let insert = |queue: &mut RxQueue, at: u32, payload: RxPayload<'_>| {
            queue
                .insert(Seq(at), payload, false, false, limit, |_, _| {})
                .new_bytes
        };
        assert_eq!(insert(&mut queue, 10, RxPayload::Borrowed(b"ab")), 2);
        assert_eq!(insert(&mut queue, 13, RxPayload::Borrowed(b"c")), 1);
        let owned = heap_frame(b"XXXXXXX", 2297);
        assert_eq!(insert(&mut queue, 8, RxPayload::Owned(owned)), 4);
        assert_eq!(queue.ofo.len(), 1);
        assert_eq!(&queue.ofo[&8].frame[..], b"XXabXcX");
        assert_eq!(queue.ofo[&8].frame.truesize(), 7);
        // Inside one entry: dropped.
        assert_eq!(insert(&mut queue, 10, RxPayload::Borrowed(b"Z")), 0);
        // Overlapping its neighbours: trimmed to the new bytes.
        assert_eq!(insert(&mut queue, 13, RxPayload::Borrowed(b"QQQQ")), 2);
        assert_eq!(insert(&mut queue, 5, RxPayload::Borrowed(b"PPPP")), 3);
        let stream: Vec<u8> = queue
            .ofo
            .values()
            .flat_map(|seg| seg.frame.to_vec())
            .collect();
        assert_eq!(stream, b"PPPXXabXcXQQ");
        assert_eq!(queue.runs.iter().collect::<Vec<_>>(), [(&5, &17)]);
        queue.debug_check();
    }
}

#[cfg(test)]
#[path = "rx_queue_tests.rs"]
mod ring_tests;
