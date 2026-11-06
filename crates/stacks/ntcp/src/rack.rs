// Bounded transmission intervals shared by RACK selection and diagnostics.
// Sequence ranges are exclusive and always smaller than half the sequence space.
use crate::{
    connection::{CallerTimebase, TimestampGranularity},
    sack::Scoreboard,
    seq::Seq,
};
#[cfg(test)]
use alloc::vec::Vec;

#[cfg(test)]
const CAPACITY: usize = 256;

// Linux Documentation/networking/ip-sysctl.rst: tcp_min_rtt_wlen defaults
// to 300 seconds, balancing path migration against transient RTT inflation.
const MIN_RTT_WINDOW: u64 = 300_000_000;
const MIN_RTT_BUCKET: u64 = MIN_RTT_WINDOW / 3;
// Even a one-caller-tick minimum can reach any u64 SRTT with this multiplier.
const MAX_MULTIPLIER: u128 = 4 * u64::MAX as u128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Interval {
    start: Seq,
    end: Seq,
    // Splits retain the original logical admission/window identity.
    original_start: Seq,
    original_end: Seq,
    // Physical originals may be smaller than the logical admission/window span.
    original_wire_start: Seq,
    original_wire_end: Seq,
    original_sent: u64,
    originally_in_window: bool,
    successful_retries: u32,
    transmission_start: Seq,
    transmission_end: Seq,
    sent: u64,
    // Retained wire TSval must still name this copy's departure time.
    timestamp_eligible: bool,
    retransmitted: bool,
    departure_committed: bool,
    // Any retransmission of the original packet makes its untouched pieces
    // ambiguous too; their ACK may have been solicited by that retransmission.
    original_retransmitted: bool,
    // One-shot byte delivery attribution is independent of transmission state.
    delivered: bool,
    // Compact statistics only; leave byte delivery and recovery independent.
    stats_flags: u8,
    sacked: bool,
    original_lost: bool,
    needs_retransmit: bool,
    // This committed retransmission copy has not shared an extra loss response.
    // Splits copy the marker; only successful retransmit commits renew it.
    loss_response_pending: bool,
}

// Independent of byte/PRR delivery: survives RTO SACK reneging.
const PACKET_DELIVERED: u8 = 1 << 0;
// Current accepted packet carries FIN; once credited, retain whether that
// credit already represented FIN even when a later copy replaces it.
const PACKET_INCLUDES_FIN: u8 = 1 << 1;
const SYN_PAYLOAD: u8 = 1 << 2;
// Independent delivery-unit boundary: latest RACK transmissions can overlap
// only part of a queued packet. Byte/SACK splits preserve this endpoint.
const DELIVERY_END: u8 = 1 << 3;
const DIAGNOSTIC_RETRY: u8 = 1 << 4;
const DIAGNOSTIC_LOST: u8 = 1 << 5;

impl Interval {
    fn stats_flag(&self, bit: u8) -> bool {
        self.stats_flags & bit != 0
    }

    fn set_stats_flag(&mut self, bit: u8, value: bool) {
        if value {
            self.stats_flags |= bit;
        } else {
            self.stats_flags &= !bit;
        }
    }
}

// Scoped to one Rack instance by the owning connection's generation. Never
// compare only sequence/time: two selections may have exactly the same values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DepartureSelection {
    generation: u64,
    start: Seq,
    end: Seq,
    selected: u64,
    retransmit: bool,
}

// Constant-size undo for one homogeneous original wire packet. Arbitrarily
// split intervals remain in place; no packet-path allocation or ledger clone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryUndo {
    start: Seq,
    end: Seq,
    prior: Interval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginalRetrySpan {
    pub original_start: Seq,
    pub original_end: Seq,
    pub originally_in_window: bool,
    pub successful_retries: u32,
    // A retry-coverage split may precede the immutable original boundary.
    pub retry_end: Seq,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counts {
    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retransmitted: u32,
}

#[derive(Debug)]
pub(crate) struct Rack {
    // No Clone/snapshot on packet paths: split copies one Interval and all
    // pushes/inserts stay inside the fallibly reserved admission capacity.
    intervals: storage::Intervals,
    capacity: usize,
    selection_generation: u64,
    departure_selection: Option<DepartureSelection>,
    timebase: CallerTimebase,
    // Transmissions before this tick give no RTT sample.
    sample_floor: u64,
    fallback: Option<Seq>,
    latest: Option<(u64, Seq)>,
    fack: Option<Seq>,
    min_rtt: Option<u64>,
    min_rtt_buckets: [Option<(u64, u64)>; 4],
    rtt: u64,
    reordering_seen: bool,
    pub(crate) reordering: u32,
    pub(crate) reordering_events: u64,
    multiplier: u128,
    persist: u8,
    pub(crate) reo_grew: bool,
    dsack_round: Option<Seq>,
    pub(crate) deadline: Option<u64>,
    pub(crate) ack_sample: Option<u64>,
    pub(crate) delivered_segments: u64,
    pub(crate) delivered_segments_valid: bool,
}

fn sent_after(a: (u64, Seq), b: (u64, Seq)) -> bool {
    a.0 > b.0 || a.0 == b.0 && a.1.after(b.1)
}

#[path = "rack_storage.rs"]
mod storage;

impl Rack {
    #[cfg(test)]
    fn new() -> Result<Self, ()> {
        Self::with_capacity(CAPACITY)
    }

    // One interval per outstanding octet is the worst case after arbitrary
    // retransmission/SACK splits; reserve control space as well.
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.intervals.allocation_bytes()
    }

    pub(crate) fn admits_bytes(&self, bytes: usize) -> bool {
        bytes
            .checked_add(2)
            .is_some_and(|needed| needed <= self.capacity)
    }

    #[cfg(test)]
    pub(crate) fn grown(&self, send_capacity: usize) -> Result<Self, ()> {
        let capacity = send_capacity.checked_add(2).ok_or(())?;
        let mut intervals = storage::Intervals::new(capacity)?;
        for interval in self.intervals.iter() {
            intervals.push(*interval);
        }
        Ok(Self {
            intervals,
            capacity,
            ..*self
        })
    }

    pub(crate) fn growth_bytes(&self, send_capacity: usize) -> Option<usize> {
        self.intervals.growth_bytes(send_capacity.checked_add(2)?)
    }

    pub(crate) fn prepare_growth(&self, send_capacity: usize) -> Result<storage::Growth, ()> {
        self.intervals
            .prepare_growth(send_capacity.checked_add(2).ok_or(())?)
    }

    pub(crate) fn commit_growth(&mut self, growth: storage::Growth, send_capacity: usize) {
        self.intervals.commit_growth(growth);
        self.capacity = send_capacity + 2;
    }

    pub(crate) fn storage_bytes(send_capacity: usize) -> Option<usize> {
        storage::Intervals::storage_bytes(send_capacity.checked_add(2)?)
    }

    #[cfg(test)]
    pub(crate) fn with_capacity(capacity: usize) -> Result<Self, ()> {
        Self::with_timebase(capacity, CallerTimebase::default())
    }

    pub(crate) fn with_timebase(capacity: usize, timebase: CallerTimebase) -> Result<Self, ()> {
        let intervals = storage::Intervals::new(capacity)?;
        Ok(Self {
            intervals,
            capacity,
            selection_generation: 0,
            departure_selection: None,
            timebase,
            sample_floor: 0,
            fallback: None,
            latest: None,
            fack: None,
            min_rtt: None,
            min_rtt_buckets: [None; 4],
            rtt: 0,
            reordering_seen: false,
            reordering: 3,
            reordering_events: 0,
            multiplier: 1,
            persist: 0,
            reo_grew: false,
            dsack_round: None,
            deadline: None,
            ack_sample: None,
            delivered_segments: 0,
            delivered_segments_valid: true,
        })
    }

    pub(crate) fn original_retry_span(
        &self,
        seq: Seq,
        proposed_end: Seq,
    ) -> Option<OriginalRetrySpan> {
        if !self.valid() || !proposed_end.after(seq) {
            return None;
        }
        let index = self
            .intervals
            .iter()
            .position(|r| !r.start.after(seq) && r.end.after(seq))?;
        let head = self.intervals[index];
        let end = self
            .intervals
            .range(index, self.intervals.len())
            .take_while(|r| {
                r.original_start == head.original_start
                    && r.original_end == head.original_end
                    && r.successful_retries == head.successful_retries
            })
            .last()?
            .end;
        Some(OriginalRetrySpan {
            original_start: head.original_start,
            original_end: head.original_end,
            originally_in_window: head.originally_in_window,
            successful_retries: head.successful_retries,
            retry_end: if end.after(proposed_end) {
                proposed_end
            } else {
                end
            },
        })
    }

    // These two commits are called only after successful wire encoding. Window
    // validity belongs to the complete original, not its surviving ACK suffix.
    pub(crate) fn commit_original_window(&mut self, start: Seq, end: Seq, in_window: bool) {
        for r in &mut self.intervals {
            if r.original_start == start && r.original_end == end {
                r.originally_in_window = in_window;
            }
        }
    }

    pub(crate) fn commit_retry_span(&mut self, start: Seq, end: Seq) {
        if !end.after(start) || !self.valid() {
            return;
        }
        if !self.split(start) || !self.split(end) {
            let boundary = self.intervals.last().map_or(end, |r| r.end);
            self.abandon(boundary);
            return;
        }
        for r in &mut self.intervals {
            if !start.after(r.start) && !r.end.after(end) {
                r.successful_retries = r.successful_retries.saturating_add(1);
            }
        }
    }

    // Preserve the last successful wire packet boundary, including partial ACKs.
    pub(crate) fn head_transmission(&self, start: Seq) -> Option<(Seq, u64)> {
        let first = self
            .intervals
            .iter()
            .position(|r| !r.start.after(start) && r.end.after(start))?;
        let head = self.intervals[first];
        let end = self
            .intervals
            .range(first, self.intervals.len())
            .take_while(|r| {
                r.sent == head.sent
                    && r.transmission_start == head.transmission_start
                    && r.transmission_end == head.transmission_end
            })
            .last()?
            .end;
        Some((end, head.sent))
    }

    pub(crate) fn valid(&self) -> bool {
        self.fallback.is_none()
    }

    pub(crate) fn min_rtt(&self) -> Option<u64> {
        self.min_rtt
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Four fixed buckets conservatively estimate a recent 300-second minimum; acknowledge contributes only eligible non-retransmitted full-transmission samples.
    //# Use the RTT measurements obtained via [RFC6298] or [RFC7323] to
    //# update the estimated minimum RTT in RACK.min_RTT.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Retains all minima within the window and at most one extra bucket; longer paths replace old minima without allocation.
    //# The sender SHOULD
    //# track a windowed min-filtered estimate of recent RTT measurements
    //# that can adapt when migrating to significantly longer paths rather
    //# than tracking a simple global minimum of all RTT measurements.
    pub(crate) fn sample(&mut self, rtt: u64, now: u64) {
        // now and RTT are caller-supplied ticks, as for acknowledge.
        // ponytail: bucket minima retain samples for 300..400 seconds, giving
        // a conservative (never higher) estimate of the exact 300-second min;
        // use a full sample deque only if exact expiration becomes necessary.
        // Like Linux tcp_update_rtt_min, aging happens on accepted samples,
        // not on timers: idle time alone does not erase the ambiguity guard.
        let epoch = now / self.timebase.ticks_from_us(MIN_RTT_BUCKET);
        let bucket = &mut self.min_rtt_buckets[(epoch % 4) as usize];
        *bucket = Some((
            epoch,
            bucket
                .filter(|old| old.0 == epoch)
                .map_or(rtt, |old| old.1.min(rtt)),
        ));
        self.min_rtt = self
            .min_rtt_buckets
            .iter()
            .flatten()
            .filter(|&&(time, _)| time <= epoch && epoch - time < 4)
            .map(|&(_, value)| value)
            .min();
        if self.latest.is_none() {
            self.rtt = rtt;
        }
    }

    pub(crate) fn discard_samples_before(&mut self, now: u64) {
        self.sample_floor = now;
    }

    // Reclaim cumulative bytes without consulting SACK advice or creating
    // delivery/RTT evidence. Trim in place: a full ledger needs no split slot.
    pub(crate) fn trim_cumulative(&mut self, ack: Seq) {
        self.acknowledge_packets(ack, None);
        self.intervals.retain_mut(|r| {
            if !r.end.after(ack) {
                if !r.stats_flag(PACKET_DELIVERED)
                    && r.end == r.transmission_end
                    && !r.stats_flag(SYN_PAYLOAD)
                {
                    self.delivered_segments_valid = false;
                }
                return false;
            }
            if ack.after(r.start) {
                r.start = ack;
            }
            true
        });
        if self.fallback.is_some_and(|boundary| !boundary.after(ack)) {
            self.fallback = None;
            self.fack = Some(ack);
        }
    }

    pub(crate) fn abandon(&mut self, boundary: Seq) {
        self.intervals.clear();
        self.delivered_segments_valid = false;
        self.departure_selection = None;
        self.fallback = Some(boundary);
        self.latest = None;
        self.deadline = None;
    }

    fn split(&mut self, edge: Seq) -> bool {
        let Some(i) = self
            .intervals
            .iter()
            .position(|r| edge.after(r.start) && r.end.after(edge))
        else {
            return true;
        };
        if self.intervals.len() == self.capacity {
            return false;
        }
        let mut right = self.intervals[i];
        right.start = edge;
        self.intervals[i].end = edge;
        self.intervals[i].set_stats_flag(DELIVERY_END, false);
        self.intervals.insert(i + 1, right);
        true
    }

    pub(crate) fn retry_undo(&self, start: Seq, end: Seq) -> Option<RetryUndo> {
        if !self.valid() || !end.after(start) {
            return None;
        }
        let prior = *self.intervals.iter().find(|r| r.start == start)?;
        if prior.sacked || !prior.needs_retransmit || prior.successful_retries == u32::MAX {
            return None;
        }
        let mut covered = start;
        for r in self
            .intervals
            .iter()
            .filter(|r| end.after(r.start) && r.end.after(start))
        {
            if r.start != covered
                || r.original_wire_start != prior.original_wire_start
                || r.original_wire_end != prior.original_wire_end
                || r.transmission_start != prior.transmission_start
                || r.transmission_end != prior.transmission_end
                || r.sent != prior.sent
                || r.timestamp_eligible != prior.timestamp_eligible
                || r.retransmitted != prior.retransmitted
                || r.departure_committed != prior.departure_committed
                || r.original_retransmitted != prior.original_retransmitted
                || r.loss_response_pending != prior.loss_response_pending
                || r.successful_retries != prior.successful_retries
                || r.sacked
                || !r.needs_retransmit
                || r.stats_flag(SYN_PAYLOAD) != prior.stats_flag(SYN_PAYLOAD)
            {
                return None;
            }
            covered = if r.end.after(end) { end } else { r.end };
        }
        (covered == end).then_some(RetryUndo { start, end, prior })
    }

    pub(crate) fn cancel_retry(&mut self, selection: DepartureSelection, undo: RetryUndo) -> bool {
        if self.departure_selection != Some(selection)
            || !self.valid()
            || !selection.retransmit
            || selection.start != undo.start
            || selection.end != undo.end
            || self.intervals.iter().any(|r| {
                undo.end.after(r.start) && r.end.after(undo.start) && r.departure_committed
            })
        {
            return false;
        }
        for r in &mut self.intervals {
            if r.original_wire_start == undo.prior.original_wire_start
                && r.original_wire_end == undo.prior.original_wire_end
            {
                r.original_retransmitted = undo.prior.original_retransmitted;
            }
            if !undo.start.after(r.start) && !r.end.after(undo.end) {
                r.transmission_start = undo.prior.transmission_start;
                r.transmission_end = undo.prior.transmission_end;
                r.sent = undo.prior.sent;
                r.timestamp_eligible = undo.prior.timestamp_eligible;
                r.retransmitted = undo.prior.retransmitted;
                r.departure_committed = undo.prior.departure_committed;
                r.loss_response_pending = undo.prior.loss_response_pending;
                r.successful_retries = undo.prior.successful_retries;
                r.needs_retransmit = undo.prior.needs_retransmit;
                r.sacked = undo.prior.sacked;
                r.set_stats_flag(SYN_PAYLOAD, undo.prior.stats_flag(SYN_PAYLOAD));
            }
        }
        self.departure_selection = None; // Generations are never rolled back.
        true
    }

    // Capture only when this output actually called transmit, not for pure ACKs.
    // The caller binds the token to its connection generation and freezes input
    // and timeout processing until the reserved output has been resolved.
    pub(crate) fn departure_selection(&self) -> Option<DepartureSelection> {
        self.departure_selection.filter(|_| self.valid())
    }

    // Shared read-only preflight lets the endpoint reject invalid departures
    // before advancing its clock. Commit uses the same edge/coverage checks.
    pub(crate) fn validate_departure(
        &self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) -> bool {
        if !self.valid()
            || self.departure_selection != Some(selection)
            || !end.after(start)
            || start.distance_from(selection.start) >= selection.end.distance_from(selection.start)
            || end.distance_from(selection.start) > selection.end.distance_from(selection.start)
            || now < selection.selected
        {
            return false;
        }
        let mut covered = start;
        for r in self
            .intervals
            .iter()
            .filter(|r| end.after(r.start) && r.end.after(start))
        {
            if r.start.after(covered)
                || r.departure_committed
                || r.sent != selection.selected
                || r.transmission_start != selection.start
                || r.transmission_end != selection.end
                || r.retransmitted != selection.retransmit
            {
                return false;
            }
            covered = if r.end.after(end) { end } else { r.end };
        }
        if covered != end {
            return false;
        }
        let splits = [start, end]
            .iter()
            .filter(|&&edge| {
                self.intervals
                    .iter()
                    .any(|r| edge.after(r.start) && r.end.after(edge))
            })
            .count();
        if splits > self.capacity.saturating_sub(self.intervals.len()) {
            return false;
        }
        true
    }

    pub(crate) fn commit_departure(
        &mut self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) -> bool {
        if !self.validate_departure(selection, start, end, now) {
            return false;
        }
        // Preflight above guarantees these cannot fail or allocate.
        let left = self.split(start);
        let right = self.split(end);
        debug_assert!(left && right);
        // Repacketize delivery units only after actual acceptance. Keep the
        // untouched prefix/suffix as separate queued units; do not tie their
        // completion to an overwritten latest-transmission sequence range.
        if let Some(previous) = self.intervals.iter_mut().find(|r| r.end == start) {
            previous.set_stats_flag(DELIVERY_END, true);
        }
        for r in &mut self.intervals {
            if !start.after(r.start) && !r.end.after(end) {
                r.set_stats_flag(DELIVERY_END, r.end == end);
                if selection.retransmit {
                    r.set_stats_flag(SYN_PAYLOAD, false);
                }
                r.set_stats_flag(DIAGNOSTIC_RETRY, selection.retransmit);
                r.set_stats_flag(DIAGNOSTIC_LOST, false);
                if !r.stats_flag(PACKET_DELIVERED) {
                    r.set_stats_flag(PACKET_INCLUDES_FIN, false);
                }
                r.sent = now;
                // Even a sub-TS-tick delay separates encoding from departure.
                r.timestamp_eligible &= now == selection.selected;
                r.transmission_start = start;
                r.transmission_end = end;
                r.departure_committed = true;
                if !selection.retransmit {
                    r.original_wire_start = start;
                    r.original_wire_end = end;
                    r.original_sent = now;
                }
            }
        }
        true
    }

    // Called only after encoding succeeds. Production reserves one interval
    // per admitted send-buffer byte plus control space; byte-edge splits cannot exhaust
    // that backing. Undersized synthetic ledgers retain a defensive fallback.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=Capacity-backed intervals retain every committed original/retransmission timestamp, including arbitrary byte splits, in caller ticks without microsecond truncation. Physical precision finer than min_RTT/4 is a caller precondition, never measured or runtime-gated; violation leaves protocol timing guarantees unspecified, not Rust UB or memory-safety violations.
    //# For each data segment sent, the sender MUST store its most recent
    //# transmission time with a timestamp whose granularity is finer
    //# than 1/4 of the minimum RTT of the connection.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.1
    //= reason=Original commit stores timestamp and clear pending loss; retransmit changes timestamp, sets retransmitted, clears needs_retransmit. original_lost is historical diagnostic state, not Segment.lost.
    //# Upon transmitting a new segment or retransmitting an old segment,
    //# record the time in Segment.xmit_ts and set Segment.lost to FALSE.
    //# Upon retransmitting a segment, set Segment.retransmitted to TRUE.
    pub(crate) fn transmit(&mut self, start: Seq, end: Seq, now: u64, retransmit: bool) {
        self.departure_selection = self.selection_generation.checked_add(1).map(|generation| {
            self.selection_generation = generation;
            DepartureSelection {
                generation,
                start,
                end,
                selected: now,
                retransmit,
            }
        });
        if let Some(boundary) = self.fallback {
            self.departure_selection = None;
            if end.after(boundary) {
                self.fallback = Some(end);
            }
            return;
        }
        if retransmit {
            if !self.split(start) || !self.split(end) {
                let boundary = self.intervals.last().map_or(end, |r| r.end);
                self.abandon(boundary);
                return;
            }
            let mut first = 0;
            while first < self.intervals.len() {
                let head = self.intervals[first];
                let mut last = first + 1;
                while last < self.intervals.len()
                    && self.intervals[last].original_wire_start == head.original_wire_start
                    && self.intervals[last].original_wire_end == head.original_wire_end
                {
                    last += 1;
                }
                if (first..last).any(|i| {
                    end.after(self.intervals[i].start) && self.intervals[i].end.after(start)
                }) {
                    for i in first..last {
                        self.intervals[i].original_retransmitted = true;
                    }
                }
                first = last;
            }
            for r in &mut self.intervals {
                if !start.after(r.start) && !r.end.after(end) {
                    r.set_stats_flag(SYN_PAYLOAD, false);
                    r.transmission_start = start;
                    r.transmission_end = end;
                    r.sent = now;
                    r.timestamp_eligible = true;
                    r.departure_committed = false;
                    r.retransmitted = true;
                    r.loss_response_pending = true;
                    r.needs_retransmit = false;
                    r.sacked = false;
                }
            }
        } else if self.intervals.len() < self.capacity {
            self.intervals.push(Interval {
                start,
                end,
                original_start: start,
                original_end: end,
                original_wire_start: start,
                original_wire_end: end,
                original_sent: now,
                originally_in_window: false,
                successful_retries: 0,
                transmission_start: start,
                transmission_end: end,
                sent: now,
                timestamp_eligible: true,
                retransmitted: false,
                departure_committed: false,
                original_retransmitted: false,
                delivered: false,
                stats_flags: 0,
                sacked: false,
                original_lost: false,
                needs_retransmit: false,
                loss_response_pending: false,
            });
        } else {
            self.abandon(end);
        }
    }

    // Returns whether an already-delivered data-only unit cannot also supply
    // the new FIN's delivery credit. Keep that control credit in Connection.
    pub(crate) fn record_fin_payload(&mut self, start: Seq, end: Seq) -> bool {
        let mut all_credited = true;
        let mut fin_credited = false;
        for r in &mut self.intervals {
            if !start.after(r.start) && !r.end.after(end) {
                all_credited &= r.stats_flag(PACKET_DELIVERED);
                fin_credited |= r.stats_flag(PACKET_DELIVERED) && r.stats_flag(PACKET_INCLUDES_FIN);
                if !r.stats_flag(PACKET_DELIVERED) {
                    r.set_stats_flag(PACKET_INCLUDES_FIN, true);
                }
            }
        }
        all_credited && !fin_credited
    }

    // Statistics use queued packetization units, as opposed to unknowable
    // physical-copy attribution. Resegmentation changes their boundaries;
    // per-byte credit survives SACK reneging and prevents repeated delivery.
    fn acknowledge_packets(&mut self, ack: Seq, scoreboard: Option<&Scoreboard>) {
        let mut start = 0;
        for end in 0..self.intervals.len() {
            if !self.intervals[end].stats_flag(DELIVERY_END) {
                continue;
            }
            let complete = self.intervals.range(start, end + 1).all(|r| {
                r.departure_committed
                    && (!r.end.after(ack)
                        || scoreboard.is_some_and(|s| {
                            s.unsacked_bytes(if r.start.after(ack) { r.start } else { ack }, r.end)
                                == 0
                        }))
            });
            if complete {
                let newly_delivered = self
                    .intervals
                    .range(start, end + 1)
                    .any(|r| !r.stats_flag(PACKET_DELIVERED) && !r.stats_flag(SYN_PAYLOAD));
                let includes_fin = self
                    .intervals
                    .range(start, end + 1)
                    .any(|r| r.stats_flag(PACKET_INCLUDES_FIN));
                if newly_delivered && self.delivered_segments_valid {
                    self.delivered_segments = self.delivered_segments.saturating_add(1);
                }
                for r in self.intervals.range_mut(start, end + 1) {
                    r.set_stats_flag(PACKET_DELIVERED, true);
                    if includes_fin && newly_delivered {
                        r.set_stats_flag(PACKET_INCLUDES_FIN, true);
                    }
                }
            }
            start = end + 1;
        }
    }

    // SYN and its payload share one wire packet, counted by Connection when
    // the SYN is acknowledged. A subsequent data repair is a distinct packet.
    pub(crate) fn record_syn_payload(&mut self, start: Seq, end: Seq) {
        for r in &mut self.intervals {
            if !start.after(r.start) && !r.end.after(end) {
                r.set_stats_flag(SYN_PAYLOAD, true);
            }
        }
    }

    // Scoreboard is authoritative. Split at its byte edges, never scan send-buffer bytes.
    // Return newly delivered bytes, counting SACK-to-cumulative transitions only once.
    #[allow(clippy::too_many_arguments)]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=DSACK grows the multiplier at most once per cumulative flight boundary.
    //# The RACK reordering window SHOULD adaptively increase (using the
    //# algorithm in "Step 4: Update RACK reordering window" below) if
    //# the sender receives a Duplicate Selective Acknowledgment (DSACK)
    //# option [RFC2883].
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=DSACK adaptation is implemented even though optional in section 4.
    //# RACK DSACK-based reordering window adaptation is RECOMMENDED but
    //# is not required.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-5.1
    //= reason=Full transmission coverage is required for latest timestamp/RTT qualification; byte delivery accounting is separately one-shot.
    //# Denotes the time when the full sequence range of RACK.segment was
    //# selectively or cumulatively acknowledged.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Scoreboard byte coverage marks delivered/SACKed intervals, cumulative transitions do not double count delivery.
    //# Given the information provided in an ACK, each segment
    //# cumulatively ACKed or SACKed is marked as delivered in the
    //# scoreboard.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Ambiguous original pieces cannot qualify; retransmitted range requires full coverage, RTT >= minimum and matching normalized local-tick TSecr when timestamps negotiated. Equality check is stricter than merely rejecting old echoes.
    //# To avoid spurious inferences, ignore a segment as invalid if any of
    //# its sequence range has been retransmitted before and if either of two
    //# conditions is true:
    //#
    //# 1.  The Timestamp Echo Reply field (TSecr) of the ACK's timestamp
    //# option [RFC7323], if available, indicates the ACK was not
    //# acknowledging the last retransmission of the segment.
    //#
    //# 2.  The segment was last retransmitted less than RACK.min_rtt ago.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Chooses most recently sent eligible full transmission for current ACK RTT; latest reference advances only by timestamp and serial end-sequence tie break.
    //# Among all the segments newly ACKed or SACKed by this ACK that pass
    //# the checks above, update the RACK.rtt to be the RTT sample calculated
    //# using this ACK.  Furthermore, record the most recent Segment.xmit_ts
    //# in RACK.xmit_ts if it is ahead of RACK.xmit_ts.  If Segment.xmit_ts
    //# equals RACK.xmit_ts (e.g., due to clock granularity limits), then
    //# compare Segment.end_seq and RACK.end_seq to break the tie when
    //# deciding whether to update the RACK.segment's associated state.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Original non-retransmitted intervals acknowledged below fack set reordering_seen; retransmitted originals are excluded.
    //# If a never-retransmitted segment
    //# that's below RACK.fack is (selectively or cumulatively) acknowledged,
    //# it has been delivered out of order.  The sender sets
    //# RACK.reordering_seen to TRUE if such a segment is identified.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Cumulative ACK covers round boundary before a new DSACK can grow multiplier and reset 16-recovery persistence.
    //# If RACK.dsack_round is not None AND
    //# SND.UNA >= RACK.dsack_round:
    //# RACK.dsack_round = None
    //# /* Grow the reordering window per round that sees DSACK.
    //# Reset the window after 16 DSACK-free recoveries */
    //# If RACK.dsack_round is None AND
    //# any DSACK option is present on latest received ACK:
    //# RACK.dsack_round = SND.NXT
    //# RACK.reo_wnd_mult += 1
    //# RACK.reo_wnd_persist = 16
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
    //# for which it is ambiguous whether the reply was for the first instance of the packet
    //# or a later instance).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# A TCP implementation MUST take at least one RTT measurement per RTT (unless that is
    //# not possible per Karn's algorithm).
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# However, when using the timestamp option, each ACK can be used as an RTT sample. RFC
    //# 1323 [JBB92] suggests that TCP connections utilizing large congestion windows should
    //# take many RTT samples per window of data to avoid aliasing effects in the estimated
    //# RTT.
    pub(crate) fn acknowledge(
        &mut self,
        ack: Seq,
        high: Seq,
        scoreboard: &Scoreboard,
        now: u64,
        echo: Option<u32>,
        timestamps: Option<TimestampGranularity>,
        mss: u32,
        dsack: bool,
    ) -> u32 {
        self.ack_sample = None;
        self.reo_grew = false;
        self.acknowledge_packets(ack, Some(scoreboard));
        if self.fallback.is_some() {
            self.trim_cumulative(ack);
            return 0;
        }
        if !self.split(ack) {
            self.abandon(high);
            return 0;
        }
        for &(left, right) in scoreboard.ranges() {
            if !self.split(left) || !self.split(right) {
                self.abandon(high);
                return 0;
            }
        }
        let mut delivered = 0;
        let mut newest: Option<(u64, Seq, u64, bool)> = None;
        let prior_fack = self.fack;
        let mut sack_reordered = false;
        let mut cumulative_reordered = false;
        for r in &mut self.intervals {
            let cumulative = !r.end.after(ack);
            let covered = cumulative || scoreboard.unsacked_bytes(r.start, r.end) == 0;
            let packet_complete = !r.transmission_end.after(ack)
                || scoreboard.unsacked_bytes(
                    if r.transmission_start.after(ack) {
                        r.transmission_start
                    } else {
                        ack
                    },
                    r.transmission_end,
                ) == 0;
            if covered && !r.sacked {
                if !r.delivered {
                    delivered += r.end.distance_from(r.start);
                    r.delivered = true;
                }
                if !r.original_retransmitted
                    && let Some(fack) = self.fack
                    && fack.after(r.end)
                {
                    self.reordering_seen = true;
                    self.reordering = self
                        .reordering
                        .max(fack.distance_from(r.start).div_ceil(mss));
                    // Preserve loss detection's existing proof. Diagnostics
                    // aggregate each evidence stage, not its split intervals;
                    // cumulative filling refers to the pre-ACK frontier.
                    if cumulative {
                        cumulative_reordered |= prior_fack.is_some_and(|old| old.after(r.end));
                    } else {
                        sack_reordered = true;
                    }
                }
                if self.fack.is_none_or(|old| r.end.after(old)) {
                    self.fack = Some(r.end);
                }
                let rtt = now.saturating_sub(r.sent);
                let eligible = packet_complete
                    && r.sent >= self.sample_floor
                    && (r.retransmitted || !r.original_retransmitted)
                    && (!r.retransmitted
                        || (rtt >= self.min_rtt.unwrap_or(u64::MAX)
                            && timestamps.is_none_or(|granularity| {
                                r.timestamp_eligible
                                    && echo
                                        == Some(granularity.tick_in(r.sent, self.timebase) as u32)
                            })));
                if eligible
                    && newest
                        .is_none_or(|old| sent_after((r.sent, r.transmission_end), (old.0, old.1)))
                {
                    newest = Some((r.sent, r.transmission_end, rtt, r.retransmitted));
                }
                r.sacked = true;
                r.original_lost = false;
                r.needs_retransmit = false;
            }
        }
        self.reordering_events = self
            .reordering_events
            .saturating_add(u64::from(sack_reordered) + u64::from(cumulative_reordered));
        if let Some((sent, end, rtt, retransmitted)) = newest {
            if !retransmitted {
                self.ack_sample = Some(rtt);
                self.sample(rtt, now);
            }
            self.rtt = rtt;
            if self.latest.is_none_or(|old| sent_after((sent, end), old)) {
                self.latest = Some((sent, end));
            }
            // Karn: retransmissions can advance RACK, not the ordinary RTT estimator.
        }
        self.intervals.retain(|r| r.end.after(ack));
        if self.dsack_round.is_some_and(|end| !end.after(ack)) {
            self.dsack_round = None;
        }
        if dsack && self.dsack_round.is_none() {
            self.dsack_round = Some(high);
            self.multiplier = self.multiplier.saturating_add(1).min(MAX_MULTIPLIER);
            self.persist = 16;
            self.reo_grew = true;
            self.reordering_seen = true;
        }
        delivered
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Fast/RTO exit decrements persistence unless this same ACK grew the window; resets multiplier on zero.
    //# Else if exiting Fast or RTO recovery:
    //# RACK.reo_wnd_persist -= 1
    //# If RACK.reo_wnd_persist <= 0:
    //# RACK.reo_wnd_mult = 1
    pub(crate) fn recovery_exit(&mut self, grew: bool) {
        if grew {
            return;
        }
        self.persist = self.persist.saturating_sub(1);
        if self.persist == 0 {
            self.multiplier = 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn adaptation(&self) -> (u128, u8) {
        (self.multiplier, self.persist)
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=Zero window without observed reordering in recovery or after three complete SACKed logical segments.
    //# The reordering window SHOULD be set to zero if no reordering has
    //# been observed on the connection so far, and either (a) three
    //# segments have been SACKed since the last recovery or (b) the
    //# sender is already in fast or RTO recovery.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=Starts at min_RTT/4 with zero for missing estimates; SRTT bound applies.
    //# Otherwise, the
    //# reordering window SHOULD start from a small fraction of the
    //# round-trip time or zero if no round-trip time estimate is
    //# available.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= reason=u128 bounded multiplier/product allows every positive u64 minimum to reach SRTT; effective window is capped at SRTT (zero if unavailable).
    //# The RACK reordering window MUST be bounded, and this bound SHOULD
    //# be SRTT.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Observed reordering preserves nonzero settling window regardless of complete SACK count/recovery.
    //# Otherwise, if some reordering has been observed, then RACK does not
    //# trigger fast recovery based on DupThresh.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Implements zeroing after three complete SACKed original wire packets or in recovery only without observed reordering; otherwise multiplies before integer division by four and caps at SRTT. Missing estimates yield zero.
    //# If RACK.reordering_seen is FALSE:
    //# If in Fast or RTO recovery:
    //# Return 0
    //# Else if RACK.segs_sacked >= DupThresh:
    //# Return 0
    //# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
    fn reo_window(&self, recovery: bool, srtt: Option<u64>) -> u64 {
        if !self.reordering_seen && (recovery || self.packet_counts().sacked >= 3) {
            return 0;
        }
        // Divide after multiplication, including minima below four caller ticks.
        // An overflowing u128 product / 4 still exceeds every u64 SRTT.
        ((u128::from(self.min_rtt.unwrap_or(0)).saturating_mul(self.multiplier) / 4)
            .min(u128::from(srtt.unwrap_or(0)))) as u64
    }

    // RFC 8985 §6.2: maximum remaining eligible interval, not minimum.
    // Return whether newly lost retransmission copies require another response.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Computes maximum remaining eligible deadline so all eligible intervals have expired when serviced; loss marking is one-shot until retransmit.
    //# For timely loss detection, it is RECOMMENDED that the
    //# sender install a reordering timer.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= reason=Uses serial tie-break, RTT+window deadline and maximum remaining deadline. needs_retransmit excludes lost intervals from pipe/repeated detection, equivalent to invalid in-flight timestamp; stored timestamp retained for diagnostics.
    //# RACK_detect_loss():
    //# timeout = 0
    //# RACK.reo_wnd = RACK_update_reo_wnd()
    //# For each segment, Segment, not acknowledged yet:
    //# If RACK_sent_after(RACK.xmit_ts, RACK.end_seq,
    //# Segment.xmit_ts, Segment.end_seq):
    //# remaining = Segment.xmit_ts + RACK.rtt +
    //# RACK.reo_wnd - Now()
    //# If remaining <= 0:
    //# Segment.lost = TRUE
    //# Segment.xmit_ts = INFINITE_TS
    //# Else:
    //# timeout = max(remaining, timeout)
    //# Return timeout
    pub(crate) fn detect(&mut self, now: u64, recovery: bool, srtt: Option<u64>) -> bool {
        self.deadline = None;
        let window = self.reo_window(recovery, srtt);
        let Some(latest) = self.latest else {
            return false;
        };
        let mut retransmission_lost = false;
        for r in &mut self.intervals {
            if r.sacked || r.needs_retransmit || !sent_after(latest, (r.sent, r.end)) {
                continue;
            }
            let deadline = r.sent.saturating_add(self.rtt).saturating_add(window);
            if now >= deadline {
                retransmission_lost |= r.retransmitted && r.loss_response_pending;
                r.original_lost = true;
                r.needs_retransmit = true;
                r.set_stats_flag(DIAGNOSTIC_LOST, true);
            } else {
                self.deadline = Some(self.deadline.map_or(deadline, |old| old.max(deadline)));
            }
        }
        if retransmission_lost {
            // Snapshot the currently committed transmission window. Later ACKs
            // losing older copies share this response, but replacements sent
            // after it renew their marker even with identical time/sequence.
            for r in &mut self.intervals {
                r.loss_response_pending = false;
            }
        }
        retransmission_lost
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.3
    //= reason=First unacknowledged interval is lost regardless of age, others only at recent RTT+window; clears SACK advice for possible reneging.
    //# Upon RTO timer expiration, RACK marks the first outstanding segment
    //# as lost (since it was sent an RTO ago); for all the other segments,
    //# RACK only marks the segment as lost if the time elapsed since the
    //# segment was transmitted is at least the sum of the recent RTT and the
    //# reordering window.
    pub(crate) fn rto(&mut self, now: u64, ack: Seq, srtt: Option<u64>) {
        let window = self.reo_window(true, srtt);
        self.deadline = None;
        for r in &mut self.intervals {
            // RTO discards prior SACK advice (possible receiver reneging).
            r.sacked = false;
            r.delivered = false;
            if r.start == ack || now >= r.sent.saturating_add(self.rtt).saturating_add(window) {
                r.original_lost = true;
                r.needs_retransmit = true;
                r.set_stats_flag(DIAGNOSTIC_LOST, true);
            }
        }
    }

    // Ordinary fast retransmit / NewReno partial ACK marks the missing head.
    // Retain the original packet edge across short retries and ledger splits.
    pub(crate) fn mark_head_lost(&mut self) {
        if let Some(end) = self.intervals.first().map(|r| r.original_wire_end) {
            for r in self
                .intervals
                .iter_mut()
                .take_while(|r| r.original_wire_end == end)
            {
                if !r.sacked {
                    r.original_lost = true;
                    r.needs_retransmit = true;
                    r.set_stats_flag(DIAGNOSTIC_LOST, true);
                }
            }
        }
    }

    pub(crate) fn mark_scoreboard_losses(&mut self, scoreboard: &Scoreboard, mss: u32) -> bool {
        let mut newly_lost = false;
        for r in &mut self.intervals {
            if !r.sacked && !r.retransmitted && scoreboard.is_lost(r.start, mss) {
                newly_lost |= !r.needs_retransmit;
                r.original_lost = true;
                r.needs_retransmit = true;
                r.set_stats_flag(DIAGNOSTIC_LOST, true);
            }
        }
        newly_lost
    }

    // SACK splits are byte accounting, not packet boundaries. Include even the
    // SACKed pieces of the highest original segment (RFC 8985 section 7.3).
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= reason=Finds highest original segment, including its SACKed pieces; MSS may clip a suffix but never select an earlier packet.
    //# If such an unsent segment is not available, then the sender SHOULD
    //# retransmit the highest-sequence segment sent so far and set
    //# TLP.is_retrans to true.
    pub(crate) fn tail_segment(&self, mss: u32) -> Option<(Seq, Seq)> {
        if !self.valid() {
            return None;
        }
        let tail = self.intervals.last()?;
        let first = self
            .intervals
            .iter()
            .rev()
            .take_while(|r| r.original_wire_end == tail.original_wire_end)
            .last()?;
        let size = tail.end.distance_from(first.start).min(mss);
        Some((tail.end.wrapping_add(0u32.wrapping_sub(size)), tail.end))
    }

    pub(crate) fn lowest_lost(&self, mss: u32) -> Option<(Seq, Seq)> {
        let first = self
            .intervals
            .iter()
            .find(|r| !r.sacked && r.needs_retransmit)?;
        // RFC 6675 §4 starts at the lowest unSACKed byte, up to SMSS;
        // §5.1 leaves post-RTO packetization unspecified. Keep RACK's original
        // packet boundary: SACK splits account bytes, not new packets (RFC 2018 §5).
        // A redundant suffix is allowed, but never include the next packet.
        let size = first.original_wire_end.distance_from(first.start).min(mss);
        Some((first.start, first.start.wrapping_add(size)))
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Valid payload ledger: unsacked and not-needs_retransmit intervals count once; successful retransmission clears needs_retransmit for only emitted bytes. Exact reordered original, lost-copy and replacement pipe values are asserted. SYN/FIN sequence space is not payload data.
    //# SACK-enabled connections using RACK-TLP loss detection
    //# [RFC8985] or other loss detection algorithms MUST calculate inflight
    //# by starting with SND.NXT - SND.UNA, subtracting out bytes SACKed in
    //# the scoreboard, subtracting out bytes marked lost in the scoreboard,
    //# and adding bytes in the scoreboard that have been retransmitted since
    //# they were last marked lost.
    pub(crate) fn pipe(&self) -> u32 {
        self.intervals
            .iter()
            .filter(|r| !r.sacked && !r.needs_retransmit)
            .map(|r| r.end.distance_from(r.start))
            .sum()
    }

    // Ranges inside [start, end) that pipe() no longer counts because they
    // await retransmission. The ledger is ordered by sequence, so a binary
    // search finds the first interval; cost follows the intervals visited.
    pub(crate) fn lost_ranges(
        &self,
        start: Seq,
        end: Seq,
    ) -> impl Iterator<Item = (Seq, Seq)> + '_ {
        let len = self.intervals.len();
        let first = if let Some(base) = self.intervals.first().map(|r| r.start) {
            let target = start.distance_from(base);
            let (mut low, mut high) = (0, len);
            if target < 1 << 31 {
                while low < high {
                    let mid = (low + high) / 2;
                    if self.intervals[mid].end.distance_from(base) <= target {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
            }
            low
        } else {
            0
        };
        self.intervals
            .range(first, len)
            .take_while(move |r| end.after(r.start))
            .filter(|r| !r.sacked && r.needs_retransmit)
            .map(move |r| {
                (
                    if r.start.after(start) { r.start } else { start },
                    if end.after(r.end) { r.end } else { end },
                )
            })
    }

    // SACK/ACK splits are not short wire packets: use the committed span.
    pub(crate) fn has_short_transmission(&self, mss: u32) -> bool {
        self.intervals
            .iter()
            .any(|r| r.transmission_end.distance_from(r.transmission_start) < mss)
    }

    // Diagnostic/accounting identity remains the logical selection, not local
    // repair packetization (which must not manufacture new loss/retry counts).
    pub(crate) fn empty_valid(&self) -> bool {
        self.valid() && self.intervals.is_empty()
    }

    // Only a whole fresh selection with no physical acceptance or feedback.
    // Generations never roll back, so a cancelled token cannot be replayed.
    pub(crate) fn cancel_unsubmitted_fresh(&mut self, selection: DepartureSelection) -> bool {
        if !self.valid()
            || self.departure_selection != Some(selection)
            || selection.retransmit
            || self.intervals.is_empty()
            || self.intervals.iter().any(|r| {
                r.departure_committed
                    || r.retransmitted
                    || r.sacked
                    || r.original_start != selection.start
                    || r.original_end != selection.end
            })
        {
            return false;
        }
        self.intervals.clear();
        self.departure_selection = None;
        true
    }

    pub(crate) fn counts(&self) -> Counts {
        self.count_by_original(false)
    }

    // Packet-unit consumers must distinguish the original wire segments of a
    // single logical admission. ACK/SACK splits preserve these boundaries;
    // later retry repacketization must not create extra original packets.
    // Linux-style queued packetization statistics are independent of the
    // original-wire identities consumed by RACK/TLP. Commit, not selection,
    // supplies boundaries and retry status; ACK/SACK splits retain them.
    pub(crate) fn diagnostic_packet_counts(&self) -> Counts {
        let mut counts = Counts::default();
        let mut start = 0;
        for end in 0..self.intervals.len() {
            if !self.intervals[end].stats_flag(DELIVERY_END) {
                continue;
            }
            let packet = || self.intervals.range(start, end + 1);
            counts.unacked += 1;
            counts.sacked += u32::from(packet().all(|r| r.sacked));
            counts.lost += u32::from(packet().any(|r| r.original_lost && !r.sacked));
            counts.retransmitted += u32::from(packet().any(|r| {
                r.stats_flag(DIAGNOSTIC_RETRY) && !r.stats_flag(DIAGNOSTIC_LOST) && !r.sacked
            }));
            start = end + 1;
        }
        counts
    }

    pub(crate) fn packet_counts(&self) -> Counts {
        self.count_by_original(true)
    }

    fn count_by_original(&self, physical: bool) -> Counts {
        let mut counts = Counts::default();
        let mut first = 0;
        while first < self.intervals.len() {
            let a = self.intervals[first];
            let mut last = first + 1;
            while last < self.intervals.len() {
                let b = self.intervals[last];
                let same = if physical {
                    a.original_wire_start == b.original_wire_start
                        && a.original_wire_end == b.original_wire_end
                } else {
                    a.original_end == b.original_end
                };
                if !same {
                    break;
                }
                last += 1;
            }
            let segment = || self.intervals.range(first, last);
            counts.unacked += 1;
            counts.sacked += u32::from(segment().all(|r| r.sacked));
            counts.lost += u32::from(segment().any(|r| r.original_lost && !r.sacked));
            counts.retransmitted +=
                u32::from(segment().any(|r| r.retransmitted && !r.sacked && !r.needs_retransmit));
            first = last;
        }
        counts
    }
}

#[cfg(test)]
#[path = "rack_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
mod diagnostic_packetization_tests {
    use super::*;
    #[test]
    fn committed_resegmentation_preserves_recovery_identity_and_rejection_snapshot() {
        let mut r = Rack::with_capacity(16).unwrap();
        r.transmit(Seq(100), Seq(1420), 0, false);
        let original = r.departure_selection().unwrap();
        assert!(r.commit_departure(original, Seq(100), Seq(1420), 0));
        assert_eq!(r.diagnostic_packet_counts().unacked, 1);
        r.mark_head_lost();
        r.transmit(Seq(100), Seq(1420), 1, true);
        let retry = r.departure_selection().unwrap();
        assert_eq!(r.diagnostic_packet_counts().unacked, 1);
        assert_eq!(r.diagnostic_packet_counts().retransmitted, 0);
        assert!(r.commit_departure(retry, Seq(100), Seq(1100), 2));
        assert_eq!(r.diagnostic_packet_counts().unacked, 2);
        assert_eq!(r.diagnostic_packet_counts().retransmitted, 1);
        assert_eq!(r.packet_counts().unacked, 1);
        assert!(r.commit_departure(retry, Seq(1100), Seq(1420), 3));
        assert_eq!(r.diagnostic_packet_counts().unacked, 2);
        assert_eq!(r.diagnostic_packet_counts().retransmitted, 2);
        assert_eq!(r.packet_counts().unacked, 1);
        assert_eq!(r.pipe(), 1320);
    }
}
