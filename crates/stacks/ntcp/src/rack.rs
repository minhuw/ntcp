// Bounded transmission intervals shared by RACK selection and diagnostics.
// Sequence ranges are exclusive and always smaller than half the sequence space.
use crate::{
    connection::{CallerTimebase, TimestampGranularity},
    sack::Scoreboard,
    seq::Seq,
};
#[cfg(test)]
use alloc::vec::Vec;
use core::cmp::Ordering;

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

fn after(a: Seq, b: Seq) -> bool {
    a.serial_cmp(b) == Some(Ordering::Greater)
}
fn sent_after(a: (u64, Seq), b: (u64, Seq)) -> bool {
    a.0 > b.0 || a.0 == b.0 && after(a.1, b.1)
}

mod storage {
    include!("rack_storage.rs");
}

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
        if !self.valid() || !after(proposed_end, seq) {
            return None;
        }
        let index = self
            .intervals
            .iter()
            .position(|r| !after(r.start, seq) && after(r.end, seq))?;
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
            retry_end: if after(end, proposed_end) {
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
        if !after(end, start) || !self.valid() {
            return;
        }
        if !self.split(start) || !self.split(end) {
            let boundary = self.intervals.last().map_or(end, |r| r.end);
            self.abandon(boundary);
            return;
        }
        for r in &mut self.intervals {
            if !after(start, r.start) && !after(r.end, end) {
                r.successful_retries = r.successful_retries.saturating_add(1);
            }
        }
    }

    // Preserve the last successful wire packet boundary, including partial ACKs.
    pub(crate) fn head_transmission(&self, start: Seq) -> Option<(Seq, u64)> {
        let first = self
            .intervals
            .iter()
            .position(|r| !after(r.start, start) && after(r.end, start))?;
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

    // Reclaim cumulative bytes without consulting SACK advice or creating
    // delivery/RTT evidence. Trim in place: a full ledger needs no split slot.
    pub(crate) fn trim_cumulative(&mut self, ack: Seq) {
        self.acknowledge_packets(ack, None);
        self.intervals.retain_mut(|r| {
            if !after(r.end, ack) {
                if !r.stats_flag(PACKET_DELIVERED)
                    && r.end == r.transmission_end
                    && !r.stats_flag(SYN_PAYLOAD)
                {
                    self.delivered_segments_valid = false;
                }
                return false;
            }
            if after(ack, r.start) {
                r.start = ack;
            }
            true
        });
        if self.fallback.is_some_and(|boundary| !after(boundary, ack)) {
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
            .position(|r| after(edge, r.start) && after(r.end, edge))
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
        if !self.valid() || !after(end, start) {
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
            .filter(|r| after(end, r.start) && after(r.end, start))
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
            covered = if after(r.end, end) { end } else { r.end };
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
                after(undo.end, r.start) && after(r.end, undo.start) && r.departure_committed
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
            if !after(undo.start, r.start) && !after(r.end, undo.end) {
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
            || !after(end, start)
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
            .filter(|r| after(end, r.start) && after(r.end, start))
        {
            if after(r.start, covered)
                || r.departure_committed
                || r.sent != selection.selected
                || r.transmission_start != selection.start
                || r.transmission_end != selection.end
                || r.retransmitted != selection.retransmit
            {
                return false;
            }
            covered = if after(r.end, end) { end } else { r.end };
        }
        if covered != end {
            return false;
        }
        let splits = [start, end]
            .iter()
            .filter(|&&edge| {
                self.intervals
                    .iter()
                    .any(|r| after(edge, r.start) && after(r.end, edge))
            })
            .count();
        if splits > self.capacity.saturating_sub(self.intervals.len()) {
            return false;
        }
        true
    }

    // Count all distinct splits before submitting an indivisible hardware group.
    pub(crate) fn validate_departure_group(
        &self,
        selection: DepartureSelection,
        start: Seq,
        size: u32,
        segments: usize,
        now: u64,
    ) -> bool {
        let Some(bytes) = (size as usize).checked_mul(segments) else {
            return false;
        };
        if size == 0 || segments < 2 || bytes >= 1 << 31 {
            return false;
        }
        let end = start.wrapping_add(bytes as u32);
        if !self.validate_departure(selection, start, end, now) {
            return false;
        }
        let splits = (0..=segments)
            .filter(|&i| {
                let edge = start.wrapping_add((i * size as usize) as u32);
                self.intervals
                    .iter()
                    .any(|r| after(edge, r.start) && after(r.end, edge))
            })
            .count();
        splits <= self.capacity.saturating_sub(self.intervals.len())
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
            if !after(start, r.start) && !after(r.end, end) {
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
            if after(end, boundary) {
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
                    after(end, self.intervals[i].start) && after(self.intervals[i].end, start)
                }) {
                    for i in first..last {
                        self.intervals[i].original_retransmitted = true;
                    }
                }
                first = last;
            }
            for r in &mut self.intervals {
                if !after(start, r.start) && !after(r.end, end) {
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
            if !after(start, r.start) && !after(r.end, end) {
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
                    && (!after(r.end, ack)
                        || scoreboard.is_some_and(|s| {
                            s.unsacked_bytes(if after(r.start, ack) { r.start } else { ack }, r.end)
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
            if !after(start, r.start) && !after(r.end, end) {
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
    // RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
    // RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
    //# for which it is ambiguous whether the reply was for the first instance of the packet
    //# or a later instance).
    // Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= reason=Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
    //# A TCP implementation MUST take at least one RTT measurement per RTT (unless that is
    //# not possible per Karn's algorithm).
    // Partial evidence only; TODO remains. RACK may advance its loss-detection RTT on retransmission; ack_sample supplied to ordinary RTO estimator is restricted to non-retransmitted, complete, unambiguous original intervals.
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
            let cumulative = !after(r.end, ack);
            let covered = cumulative || scoreboard.unsacked_bytes(r.start, r.end) == 0;
            let packet_complete = !after(r.transmission_end, ack)
                || scoreboard.unsacked_bytes(
                    if after(r.transmission_start, ack) {
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
                    && after(fack, r.end)
                {
                    self.reordering_seen = true;
                    self.reordering = self
                        .reordering
                        .max(fack.distance_from(r.start).div_ceil(mss));
                    // Preserve loss detection's existing proof. Diagnostics
                    // aggregate each evidence stage, not its split intervals;
                    // cumulative filling refers to the pre-ACK frontier.
                    if cumulative {
                        cumulative_reordered |= prior_fack.is_some_and(|old| after(old, r.end));
                    } else {
                        sack_reordered = true;
                    }
                }
                if self.fack.is_none_or(|old| after(r.end, old)) {
                    self.fack = Some(r.end);
                }
                let rtt = now.saturating_sub(r.sent);
                let eligible = packet_complete
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
        self.intervals.retain(|r| after(r.end, ack));
        if self.dsack_round.is_some_and(|end| !after(end, ack)) {
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
pub(crate) mod tests {
    use super::*;

    mod statistics {
        include!("rack_statistics_tests.rs");
    }

    // Original physical wire span/time plus whether any of that original
    // packet has been retransmitted.
    pub(crate) fn original_packet(rack: &Rack, start: Seq) -> Option<(Seq, Seq, u64, bool)> {
        rack.intervals
            .iter()
            .find(|r| !after(r.start, start) && after(r.end, start))
            .map(|r| {
                (
                    r.original_wire_start,
                    r.original_wire_end,
                    r.original_sent,
                    r.original_retransmitted,
                )
            })
    }

    #[test]
    fn blocked_storage_preserves_cross_block_packet_identity_and_byte_splits() {
        let mut rack = Rack::with_capacity(2048).unwrap();
        let base = Seq(u32::MAX - 1000);
        let end = base.wrapping_add(2048);
        rack.transmit(base, end, 10, false);
        let token = rack.departure_selection().unwrap();
        assert!(rack.commit_departure(token, base, end, 10));
        crate::allocation_tests::fail_after(0, || {
            for byte in 0..2048 {
                rack.transmit(
                    base.wrapping_add(byte),
                    base.wrapping_add(byte + 1),
                    20,
                    true,
                );
            }
            assert!(rack.valid());
            assert_eq!(rack.intervals.len(), 2048);
            assert_eq!(rack.counts().unacked, 1);
            assert_eq!(rack.counts().retransmitted, 1);
            assert_eq!(
                rack.head_transmission(base),
                Some((base.wrapping_add(1), 20))
            );
        });
        let first = rack.intervals.as_ptr();
        let grown = rack.prepare_growth(4094).unwrap();
        rack.commit_growth(grown, 4094);
        assert_eq!(rack.intervals.as_ptr(), first); // Full blocks never move.
        crate::allocation_tests::fail_after(0, || rack.trim_cumulative(base.wrapping_add(1500)));
        assert_eq!(rack.intervals.len(), 548);
        assert_eq!(rack.intervals[0].start, base.wrapping_add(1500));
        assert_eq!(rack.intervals.last().unwrap().end, end);
        assert_eq!(rack.counts().unacked, 1);
    }

    mod local_repair {
        include!("rack_local_repair_tests.rs");
    }

    fn sack(
        rack: &mut Rack,
        scoreboard: &mut Scoreboard,
        ack: u32,
        high: u32,
        now: u64,
        blocks: &[(u32, u32)],
    ) -> u32 {
        let mut wire = [None; 4];
        for (slot, &block) in wire.iter_mut().zip(blocks) {
            *slot = Some(block);
        }
        let update = scoreboard.update(Seq(ack), Seq(high), &wire);
        rack.acknowledge(
            Seq(ack),
            Seq(high),
            scoreboard,
            now,
            None,
            None,
            1000,
            update.dsack,
        )
    }

    #[test]
    fn departure_timestamp_evidence_requires_unchanged_encoding_time() {
        for scale in [1, 1000] {
            let timebase = CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            };
            for granularity in [
                TimestampGranularity::Milliseconds,
                TimestampGranularity::Microseconds,
            ] {
                let tick = timebase.ticks_from_us(granularity.tick_us());
                let selected = 300_000 * scale;
                // One caller tick includes sub-wire-tick delays where supported.
                for delay in [0, 1, tick] {
                    let accepted = selected + delay;
                    for echo_time in [selected, accepted] {
                        for retransmit in [false, true] {
                            for timestamps in [None, Some(granularity)] {
                                let mut rack = Rack::with_timebase(4, timebase).unwrap();
                                rack.sample(100_000 * scale, 0);
                                if retransmit {
                                    rack.transmit(Seq(0), Seq(8), 100_000 * scale, false);
                                }
                                rack.transmit(Seq(0), Seq(8), selected, retransmit);
                                let token = rack.departure_selection().unwrap();
                                assert!(rack.commit_departure(token, Seq(0), Seq(8), accepted));
                                assert_eq!(rack.intervals[0].timestamp_eligible, delay == 0);
                                assert_eq!(
                                    rack.acknowledge(
                                        Seq(8),
                                        Seq(8),
                                        &Scoreboard::new(),
                                        accepted + 100_000 * scale,
                                        Some(granularity.tick_in(echo_time, timebase) as u32),
                                        timestamps,
                                        1000,
                                        false,
                                    ),
                                    8
                                );
                                let eligible = !retransmit || timestamps.is_none() || delay == 0;
                                assert_eq!(rack.latest, eligible.then_some((accepted, Seq(8))));
                                assert_eq!(
                                    rack.ack_sample,
                                    (!retransmit).then_some(100_000 * scale)
                                );
                                assert_eq!(rack.min_rtt, Some(100_000 * scale));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn departure_timestamp_eligibility_survives_splits_and_renews_only_on_transmit() {
        let mut rack = Rack::with_capacity(24).unwrap();
        rack.sample(100_000, 0);
        rack.transmit(Seq(0), Seq(24), 100_000, false);
        rack.transmit(Seq(0), Seq(24), 300_000, true);
        let token = rack.departure_selection().unwrap();
        // Accept a delayed middle first, then independently accept its siblings.
        assert!(rack.commit_departure(token, Seq(8), Seq(16), 300_001));
        assert!(rack.commit_departure(token, Seq(0), Seq(8), 300_000));
        assert!(rack.commit_departure(token, Seq(16), Seq(24), 301_000));
        assert_eq!(
            rack.intervals
                .iter()
                .map(|r| r.timestamp_eligible)
                .collect::<Vec<_>>(),
            [true, false, false]
        );
        let mut scoreboard = Scoreboard::new();
        scoreboard.update(Seq(0), Seq(24), &[Some((10, 14)), None, None, None]);
        assert_eq!(
            rack.acknowledge(
                Seq(0),
                Seq(24),
                &scoreboard,
                401_000,
                Some(300),
                Some(TimestampGranularity::Milliseconds),
                1000,
                false,
            ),
            4
        );
        assert_eq!(rack.latest, None);
        assert!(
            rack.intervals
                .iter()
                .filter(|r| r.start != Seq(0))
                .all(|r| !r.timestamp_eligible)
        );
        // The on-time sibling qualifies despite both delayed siblings.
        assert_eq!(
            rack.acknowledge(
                Seq(8),
                Seq(24),
                &scoreboard,
                401_000,
                Some(300),
                Some(TimestampGranularity::Milliseconds),
                1000,
                false,
            ),
            8
        );
        assert_eq!(rack.latest, Some((300_000, Seq(8))));
        // Newly encoded network retransmission renews only its exact byte span,
        // including pieces created by the earlier SACK split.
        rack.transmit(Seq(8), Seq(16), 500_000, true);
        let token = rack.departure_selection().unwrap();
        assert!(rack.commit_departure(token, Seq(8), Seq(16), 500_000));
        assert!(
            rack.intervals
                .iter()
                .all(|r| r.timestamp_eligible == (r.end.0 <= 16))
        );
        assert_eq!(
            rack.acknowledge(
                Seq(24),
                Seq(24),
                &Scoreboard::new(),
                600_000,
                Some(500),
                Some(TimestampGranularity::Milliseconds),
                1000,
                false,
            ),
            12
        );
        assert_eq!(rack.latest, Some((500_000, Seq(16))));
        assert_eq!(rack.ack_sample, None);
    }

    #[test]
    fn departure_fresh_fragments_preserve_logical_coverage_and_wrap() {
        for base in [Seq(100), Seq(u32::MAX - 9)] {
            let seq = |n| base.wrapping_add(n);
            let mut rack = Rack::with_capacity(24).unwrap();
            rack.transmit(base, seq(24), 10, false);
            rack.commit_original_window(base, seq(24), true);
            let token = rack.departure_selection().unwrap();
            let span = rack.original_retry_span(base, seq(24)).unwrap();
            let counts = rack.counts();
            assert!(rack.commit_departure(token, seq(4), seq(12), 100));
            assert!(rack.commit_departure(token, base, seq(4), 200));
            assert_eq!(rack.head_transmission(base), Some((seq(4), 200)));
            assert_eq!(rack.head_transmission(seq(4)), Some((seq(12), 100)));
            assert_eq!(rack.head_transmission(seq(12)), Some((seq(24), 10)));
            assert_eq!(
                original_packet(&rack, base),
                Some((base, seq(4), 200, false))
            );
            assert_eq!(
                original_packet(&rack, seq(4)),
                Some((seq(4), seq(12), 100, false))
            );
            assert_eq!(rack.original_retry_span(base, seq(24)), Some(span));
            assert!(rack.commit_departure(token, seq(12), seq(24), 300));
            assert_eq!(rack.head_transmission(base), Some((seq(4), 200)));
            assert_eq!(
                original_packet(&rack, seq(12)),
                Some((seq(12), seq(24), 300, false))
            );
            assert_eq!(rack.counts().unacked, counts.unacked);
            assert_eq!(rack.counts().lost, 0);
            assert_eq!(rack.counts().retransmitted, 0);
            assert_eq!(rack.pipe(), 24);
            assert!(rack.intervals.iter().all(|r| !r.delivered
                && !r.sacked
                && !r.retransmitted
                && !r.loss_response_pending
                && r.successful_retries == 0));

            assert_eq!(rack.tail_segment(100), Some((seq(12), seq(24))));
            rack.mark_head_lost();
            assert_eq!(rack.lowest_lost(100), Some((base, seq(4))));
            assert!(
                !rack
                    .intervals
                    .iter()
                    .find(|r| r.start == seq(4))
                    .unwrap()
                    .needs_retransmit
            );

            // A real retry now makes only its physical original ambiguous,
            // without splitting the original window/first-retry permission.
            rack.transmit(base, seq(2), 400, true);
            rack.commit_retry_span(base, seq(2));
            assert!(original_packet(&rack, seq(3)).unwrap().3);
            assert!(!original_packet(&rack, seq(4)).unwrap().3);
            assert_eq!(
                rack.original_retry_span(seq(4), seq(24))
                    .unwrap()
                    .successful_retries,
                0
            );
        }
    }

    #[test]
    fn departure_retry_preserves_history_and_one_shot_delivery() {
        for base in [Seq(100), Seq(u32::MAX - 9)] {
            let seq = |n| base.wrapping_add(n);
            let mut rack = Rack::with_capacity(24).unwrap();
            rack.transmit(base, seq(24), 10, false);
            rack.commit_original_window(base, seq(24), true);
            rack.mark_head_lost();
            rack.transmit(base, seq(24), 20, true);
            rack.commit_retry_span(base, seq(24));
            rack.transmit(seq(4), seq(20), 30, true);
            rack.commit_retry_span(seq(4), seq(20));
            let token = rack.departure_selection().unwrap();
            // Existing delivery, SACK and loss state is not reset by departure.
            let r = &mut rack.intervals[1];
            r.delivered = true;
            r.sacked = true;
            r.needs_retransmit = true;
            r.set_stats_flag(DIAGNOSTIC_LOST, true);
            let before = *r;
            let counts = rack.counts();
            let pipe = rack.pipe();
            let original = original_packet(&rack, seq(4));
            assert!(rack.commit_departure(token, seq(8), seq(16), 100));
            let accepted = rack.intervals.iter().find(|r| r.start == seq(8)).unwrap();
            let expected = Interval {
                start: seq(8),
                end: seq(16),
                sent: 100,
                timestamp_eligible: false,
                transmission_start: seq(8),
                transmission_end: seq(16),
                departure_committed: true,
                stats_flags: (before.stats_flags | DELIVERY_END | DIAGNOSTIC_RETRY)
                    & !DIAGNOSTIC_LOST,
                ..before
            };
            assert_eq!(*accepted, expected);
            assert_eq!(rack.head_transmission(seq(4)), Some((seq(8), 30)));
            assert_eq!(rack.head_transmission(seq(16)), Some((seq(20), 30)));
            assert_eq!(original_packet(&rack, seq(8)), original);
            assert_eq!(rack.counts().unacked, counts.unacked);
            assert_eq!(rack.counts().sacked, counts.sacked);
            assert_eq!(rack.counts().lost, counts.lost);
            assert_eq!(rack.counts().retransmitted, counts.retransmitted);
            assert_eq!(rack.pipe(), pipe);
            assert!(rack.commit_departure(token, seq(4), seq(8), 110));
            assert!(rack.commit_departure(token, seq(16), seq(20), 120));
            assert_eq!(rack.head_transmission(seq(8)), Some((seq(16), 100)));
            let mut scoreboard = Scoreboard::new();
            assert_eq!(
                sack(&mut rack, &mut scoreboard, seq(24).0, seq(24).0, 500, &[]),
                8
            );
            assert_eq!(rack.ack_sample, None); // Karn still applies.
            assert_eq!(
                sack(&mut rack, &mut scoreboard, seq(24).0, seq(24).0, 600, &[]),
                0
            );
        }
    }

    #[test]
    fn departure_retry_crosses_physical_originals_without_rewriting_history() {
        let mut rack = Rack::with_capacity(24).unwrap();
        rack.transmit(Seq(0), Seq(24), 10, false);
        let fresh = rack.departure_selection().unwrap();
        assert!(rack.commit_departure(fresh, Seq(0), Seq(8), 20));
        assert!(rack.commit_departure(fresh, Seq(8), Seq(24), 30));
        rack.transmit(Seq(4), Seq(20), 40, true);
        rack.commit_retry_span(Seq(4), Seq(20));
        let retry = rack.departure_selection().unwrap();
        assert!(rack.commit_departure(retry, Seq(6), Seq(16), 50));
        assert_eq!(
            original_packet(&rack, Seq(6)),
            Some((Seq(0), Seq(8), 20, true))
        );
        assert_eq!(
            original_packet(&rack, Seq(8)),
            Some((Seq(8), Seq(24), 30, true))
        );
        assert_eq!(rack.head_transmission(Seq(6)), Some((Seq(16), 50)));
        assert!(
            rack.intervals
                .iter()
                .filter(|r| !after(Seq(4), r.start) && !after(r.end, Seq(20)))
                .all(|r| r.successful_retries == 1 && r.retransmitted && r.loss_response_pending)
        );
        rack.abandon(Seq(24));
        let before = alloc::format!("{rack:?}");
        assert!(!rack.commit_departure(retry, Seq(4), Seq(6), 60));
        assert_eq!(alloc::format!("{rack:?}"), before);
        assert_eq!(rack.departure_selection(), None);
    }

    #[test]
    fn group_departure_preflight_capacity_wrap_and_distinct_physical_identity() {
        for base in [Seq(100), Seq(u32::MAX - 15)] {
            for capacity in [3, 4] {
                let mut rack = Rack::with_capacity(capacity).unwrap();
                rack.transmit(base, base.wrapping_add(32), 10, false);
                let token = rack.departure_selection().unwrap();
                let before = alloc::format!("{rack:?}");
                for (size, count, now) in [
                    (0, 3, 20),
                    (8, 1, 20),
                    (8, usize::MAX, 20),
                    (8, 3, 9),
                    (u32::MAX, 3, 20),
                ] {
                    assert!(!rack.validate_departure_group(token, base, size, count, now));
                }
                assert_eq!(
                    rack.validate_departure_group(token, base, 8, 3, 20),
                    capacity == 4
                );
                assert_eq!(alloc::format!("{rack:?}"), before);
                if capacity == 3 {
                    // Scalar fallback still works when the whole prefix cannot.
                    assert!(rack.commit_departure(token, base, base.wrapping_add(8), 20));
                    continue;
                }
                crate::allocation_tests::fail_after(0, || {
                    for n in 0..3 {
                        assert!(rack.commit_departure(
                            token,
                            base.wrapping_add(n * 8),
                            base.wrapping_add((n + 1) * 8),
                            20
                        ));
                    }
                });
                for n in 0..3 {
                    let start = base.wrapping_add(n * 8);
                    let end = base.wrapping_add((n + 1) * 8);
                    assert_eq!(rack.head_transmission(start), Some((end, 20)));
                    assert_eq!(original_packet(&rack, start), Some((start, end, 20, false)));
                }
                assert!(!rack.intervals.last().unwrap().departure_committed);
                assert!(!rack.validate_departure_group(token, base, 8, 3, 20));
                assert!(rack.commit_departure(
                    token,
                    base.wrapping_add(24),
                    base.wrapping_add(32),
                    30
                ));
                assert_eq!(
                    rack.head_transmission(base.wrapping_add(24)),
                    Some((base.wrapping_add(32), 30))
                );
            }
        }
    }

    #[test]
    fn departure_capacity_no_allocation_and_failure_atomicity() {
        let mut rack = Rack::with_capacity(256).unwrap();
        rack.transmit(Seq(0), Seq(256), 10, false);
        let token = rack.departure_selection().unwrap();
        let bytes = rack.allocation_bytes();
        let ptr = rack.intervals.as_ptr();
        crate::allocation_tests::fail_after(0, || {
            for n in 0..256 {
                assert!(rack.commit_departure(token, Seq(n), Seq(n + 1), 100 + u64::from(n)));
            }
            assert_eq!(rack.intervals.len(), rack.capacity);
            assert_eq!(rack.intervals.as_ptr(), ptr);
            assert_eq!(rack.allocation_bytes(), bytes);
        });
        for (n, r) in rack.intervals.iter().enumerate() {
            assert_eq!(r.sent, 100 + n as u64);
            assert_eq!(r.original_sent, r.sent);
            assert_eq!(r.successful_retries, 0);
        }
        // Two edges need two slots: do not apply the first split on failure.
        let mut rack = Rack::with_capacity(2).unwrap();
        rack.transmit(Seq(0), Seq(8), 10, false);
        let token = rack.departure_selection().unwrap();
        let before = alloc::format!("{rack:?}");
        assert!(!rack.commit_departure(token, Seq(2), Seq(6), 20));
        assert_eq!(alloc::format!("{rack:?}"), before);
        assert!(rack.commit_departure(token, Seq(0), Seq(4), 20));
        // A full ledger still accepts an already aligned suffix without a slot.
        crate::allocation_tests::fail_after(0, || {
            assert!(rack.commit_departure(token, Seq(4), Seq(8), 30));
        });
    }

    #[test]
    fn departure_rejects_stale_duplicate_invalid_and_exhausted_tokens() {
        let mut rack = Rack::with_capacity(24).unwrap();
        rack.transmit(Seq(0), Seq(24), 10, false);
        let old = rack.departure_selection().unwrap();
        rack.transmit(Seq(0), Seq(24), 10, true);
        let older_retry = rack.departure_selection().unwrap();
        rack.transmit(Seq(0), Seq(24), 10, true);
        let token = rack.departure_selection().unwrap();
        for (t, start, end, now) in [
            (old, 0, 24, 20),
            (older_retry, 0, 24, 20),
            (token, 0, 24, 9),
            (token, 0, 25, 20),
            (token, u32::MAX, 10, 20),
            (token, 4, 4, 20),
            (token, 10, 4, 20),
        ] {
            let before = alloc::format!("{rack:?}");
            assert!(!rack.commit_departure(t, Seq(start), Seq(end), now));
            assert_eq!(alloc::format!("{rack:?}"), before);
        }
        assert!(rack.commit_departure(token, Seq(0), Seq(8), 10));
        let before = alloc::format!("{rack:?}");
        assert!(!rack.commit_departure(token, Seq(0), Seq(8), 10));
        assert!(!rack.commit_departure(token, Seq(4), Seq(12), 20));
        assert_eq!(alloc::format!("{rack:?}"), before);
        // A removed byte cannot be silently covered by a departure commit.
        rack.intervals[1].start = Seq(9);
        let before = alloc::format!("{rack:?}");
        assert!(!rack.commit_departure(token, Seq(8), Seq(24), 20));
        assert_eq!(alloc::format!("{rack:?}"), before);
        rack.selection_generation = u64::MAX;
        rack.transmit(Seq(0), Seq(24), 10, true);
        assert_eq!(rack.departure_selection(), None);
        assert!(!rack.commit_departure(token, Seq(8), Seq(24), 20));
        rack.transmit(Seq(0), Seq(24), 10, true);
        assert_eq!(rack.departure_selection(), None);
    }

    #[test]
    fn departure_fresh_ack_uses_physical_packet_boundary_and_age() {
        let mut rack = Rack::with_capacity(24).unwrap();
        rack.transmit(Seq(0), Seq(24), 10, false);
        let token = rack.departure_selection().unwrap();
        assert!(rack.commit_departure(token, Seq(0), Seq(8), 100));
        assert!(rack.commit_departure(token, Seq(8), Seq(24), 200));
        let mut scoreboard = Scoreboard::new();
        assert_eq!(sack(&mut rack, &mut scoreboard, 8, 24, 210, &[]), 8);
        assert_eq!(rack.latest, Some((100, Seq(8))));
        assert_eq!(rack.ack_sample, Some(110));
        assert_eq!(rack.head_transmission(Seq(8)), Some((Seq(24), 200)));
        assert_eq!(sack(&mut rack, &mut scoreboard, 24, 24, 220, &[]), 16);
        assert_eq!(rack.ack_sample, Some(20));
    }

    #[test]
    fn original_retry_identity_and_coverage_survive_sack_ack_and_replacement() {
        for base in [Seq(100), Seq(u32::MAX - 9)] {
            let end = base.wrapping_add(24);
            let mut rack = Rack::with_capacity(26).unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.transmit(base, end, 10, false);
            rack.commit_original_window(base, end, true);
            rack.transmit(base, base.wrapping_add(8), 20, true);
            rack.commit_retry_span(base, base.wrapping_add(8));
            // A replacement changes RACK's copy/time, not original identity.
            rack.transmit(base.wrapping_add(4), base.wrapping_add(6), 30, true);
            rack.commit_retry_span(base.wrapping_add(4), base.wrapping_add(6));
            sack(
                &mut rack,
                &mut scoreboard,
                base.wrapping_add(2).0,
                end.0,
                40,
                &[(base.wrapping_add(5).0, base.wrapping_add(10).0)],
            );
            for (offset, retries, retry_end) in [(2, 1, 4), (4, 2, 6), (6, 1, 8), (8, 0, 24)] {
                let span = rack
                    .original_retry_span(base.wrapping_add(offset), end)
                    .unwrap();
                assert_eq!(span.original_start, base);
                assert_eq!(span.original_end, end);
                assert!(span.originally_in_window);
                assert_eq!(span.successful_retries, retries);
                assert_eq!(span.retry_end, base.wrapping_add(retry_end));
                assert_eq!(
                    original_packet(&rack, base.wrapping_add(offset)),
                    Some((base, end, 10, true))
                );
            }
            assert_eq!(rack.original_retry_span(base, end), None);
            // Pure queries, unrelated ACKs and splits never spend suffix credit.
            let suffix = rack
                .original_retry_span(base.wrapping_add(10), end)
                .unwrap();
            sack(
                &mut rack,
                &mut scoreboard,
                base.wrapping_add(3).0,
                end.0,
                50,
                &[],
            );
            assert_eq!(
                rack.original_retry_span(base.wrapping_add(10), end)
                    .unwrap(),
                suffix
            );
        }
    }

    #[test]
    fn retry_coverage_overflow_discards_permission_not_payload_or_inferred_time() {
        let mut rack = Rack::with_capacity(1).unwrap();
        rack.transmit(Seq(100), Seq(108), 10, false);
        rack.commit_original_window(Seq(100), Seq(108), true);
        assert!(
            rack.original_retry_span(Seq(100), Seq(108))
                .unwrap()
                .originally_in_window
        );
        rack.commit_retry_span(Seq(100), Seq(104));
        assert!(!rack.valid());
        assert_eq!(rack.original_retry_span(Seq(104), Seq(108)), None);
        assert_eq!(rack.head_transmission(Seq(100)), None);
        rack.transmit(Seq(104), Seq(108), 20, true);
        assert_eq!(rack.original_retry_span(Seq(104), Seq(108)), None);
        assert_eq!(rack.fallback, Some(Seq(108)));
    }
    #[test]
    fn caller_units_scale_minimum_aging_and_retransmission_echoes() {
        for scale in [1, 1000] {
            let timebase = CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            };
            let mut rack = Rack::with_timebase(4, timebase).unwrap();
            rack.sample(50 * scale, 0);
            rack.sample(400 * scale, MIN_RTT_WINDOW * scale);
            assert_eq!(rack.min_rtt, Some(50 * scale));
            rack.sample(400 * scale, (MIN_RTT_WINDOW + MIN_RTT_BUCKET) * scale);
            assert_eq!(rack.min_rtt, Some(400 * scale));
            let mut bounded = Rack::with_timebase(1, timebase).unwrap();
            bounded.transmit(Seq(0), Seq(2), 0, false);
            bounded.transmit(Seq(1), Seq(2), scale, true);
            assert!(!bounded.valid()); // Capacity fallback is unit-independent.
            for granularity in [
                TimestampGranularity::Milliseconds,
                TimestampGranularity::Microseconds,
            ] {
                let mut rack = Rack::with_timebase(4, timebase).unwrap();
                rack.sample(100_000 * scale, 0);
                rack.transmit(Seq(0), Seq(1000), 100_000 * scale, false);
                rack.transmit(Seq(0), Seq(1000), 300_000 * scale, true);
                rack.acknowledge(
                    Seq(1000),
                    Seq(1000),
                    &Scoreboard::new(),
                    400_000 * scale,
                    Some(granularity.tick(300_000) as u32),
                    Some(granularity),
                    1000,
                    false,
                );
                assert_eq!(rack.latest, Some((300_000 * scale, Seq(1000))));
                assert_eq!(rack.rtt, 100_000 * scale);
                assert_eq!(rack.ack_sample, None); // Karn exclusion unchanged.
            }
        }
    }

    #[test]
    fn capacity_backing_keeps_every_byte_timestamp_after_splits() {
        let mut rack = Rack::with_capacity(514).unwrap();
        let storage = (rack.intervals.as_ptr(), rack.intervals.capacity());
        rack.transmit(Seq(0), Seq(512), 0, false);
        for byte in 0..512 {
            rack.transmit(Seq(byte), Seq(byte + 1), byte as u64 + 1, true);
        }
        assert!(rack.valid());
        assert_eq!(
            (rack.intervals.as_ptr(), rack.intervals.capacity()),
            storage
        );
        assert_eq!(rack.intervals.len(), 512);
        assert_eq!(
            original_packet(&rack, Seq(255)),
            Some((Seq(0), Seq(512), 0, true))
        );
        for byte in 0..512 {
            assert_eq!(
                rack.head_transmission(Seq(byte)),
                Some((Seq(byte + 1), byte as u64 + 1))
            );
        }
        rack.acknowledge(
            Seq(511),
            Seq(512),
            &Scoreboard::new(),
            1000,
            None,
            None,
            512,
            false,
        );
        assert_eq!(
            (rack.intervals.as_ptr(), rack.intervals.capacity()),
            storage
        );
        assert_eq!(Rack::storage_bytes(usize::MAX), None);
        assert!(Rack::with_capacity(usize::MAX).is_err());
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks partial SACK and tail probe credit, repeated SACK no credit, and RTO reneging reset.
    //# Given the information provided in an ACK, each segment
    //# cumulatively ACKed or SACKed is marked as delivered in the
    //# scoreboard.
    fn partial_sack_delivery_is_one_shot_across_tail_probe_and_resets_at_rto() {
        for base in [Seq(0), Seq(u32::MAX - 1999)] {
            let seq = |n: u32| base.wrapping_add(n);
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.sample(100_000, 0);
            for n in 0..4 {
                rack.transmit(seq(n * 1000), seq((n + 1) * 1000), 100_000, false);
            }
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    base.0,
                    seq(4000).0,
                    200_000,
                    &[(seq(3500).0, seq(4000).0)]
                ),
                500
            );
            rack.transmit(seq(3000), seq(4000), 300_000, true);
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    base.0,
                    seq(4000).0,
                    400_000,
                    &[(seq(3000).0, seq(4000).0)]
                ),
                500
            );
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    base.0,
                    seq(4000).0,
                    400_001,
                    &[(seq(3000).0, seq(4000).0)]
                ),
                0
            );
            rack.rto(500_000, base, Some(100_000));
            scoreboard.clear(); // Possible receiver reneging starts fresh attribution.
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    base.0,
                    seq(4000).0,
                    600_000,
                    &[(seq(3000).0, seq(4000).0)]
                ),
                1000
            );
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Longer-path samples replace expired minima; bucket boundaries never discard in-window minima, idle time alone retains the guard, and equal/shorter samples update immediately.
    //# The sender SHOULD
    //# track a windowed min-filtered estimate of recent RTT measurements
    //# that can adapt when migrating to significantly longer paths rather
    //# than tracking a simple global minimum of all RTT measurements.
    fn windowed_minimum_path_migration_and_boundaries() {
        for start in [0, MIN_RTT_BUCKET - 1, MIN_RTT_BUCKET] {
            let mut rack = Rack::new().unwrap();
            rack.sample(100, start);
            rack.sample(400, start + MIN_RTT_WINDOW);
            assert_eq!(rack.min_rtt, Some(100)); // Inclusive window boundary.
            rack.sample(400, start + MIN_RTT_WINDOW + MIN_RTT_BUCKET);
            assert_eq!(rack.min_rtt, Some(400));
            assert_eq!(rack.reo_window(false, Some(400)), 100);
            rack.sample(50, start + MIN_RTT_WINDOW + MIN_RTT_BUCKET);
            assert_eq!(rack.min_rtt, Some(50));
        }
        let mut boundary = Rack::new().unwrap();
        boundary.sample(100, 0);
        boundary.sample(400, 4 * MIN_RTT_BUCKET - 1);
        assert_eq!(boundary.min_rtt, Some(100));
        boundary.sample(400, 4 * MIN_RTT_BUCKET);
        assert_eq!(boundary.min_rtt, Some(400)); // Old ring slot reused exactly here.

        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        rack.detect(10 * MIN_RTT_WINDOW, false, Some(400));
        assert_eq!(rack.min_rtt, Some(100)); // No accepted sample, no aging.
        let sent = 10 * MIN_RTT_WINDOW;
        rack.transmit(Seq(0), Seq(1000), sent, false);
        sack(&mut rack, &mut scoreboard, 1000, 1000, sent + 400, &[]);
        assert_eq!(rack.min_rtt, Some(400));
        assert_eq!(rack.ack_sample, Some(400));
        // The new path minimum is also the retransmission ambiguity threshold.
        rack.transmit(Seq(1000), Seq(2000), sent + 500, false);
        rack.transmit(Seq(1000), Seq(2000), sent + 600, true);
        let latest = rack.latest;
        sack(&mut rack, &mut scoreboard, 2000, 2000, sent + 999, &[]);
        assert_eq!(rack.latest, latest);
        assert_eq!(rack.ack_sample, None);
        assert_eq!(rack.min_rtt, Some(400));

        // Epoch arithmetic does not overflow at the clock's representable end.
        rack.sample(800, u64::MAX - 1);
        assert_eq!(rack.min_rtt, Some(800));
        rack.sample(700, u64::MAX);
        assert_eq!(rack.min_rtt, Some(700));
        rack.sample(0, u64::MAX);
        assert_eq!(rack.min_rtt, Some(0));
        assert_eq!(rack.reo_window(false, Some(u64::MAX)), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Four hundred distinct DSACK rounds grow beyond 255 to SRTT, duplicate same-round ACKs do not grow, and widened arithmetic reaches even u64::MAX caps without overflow.
    //# If RACK.dsack_round is None AND
    //# any DSACK option is present on latest received ACK:
    //# RACK.dsack_round = SND.NXT
    //# RACK.reo_wnd_mult += 1
    //# RACK.reo_wnd_persist = 16
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks multiplication before division, absent/zero SRTT, and overflow-safe SRTT bounds for all representative u64 minima.
    //# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= type=test
    //= reason=Effective window never exceeds SRTT, including maximum representable inputs.
    //# The RACK reordering window MUST be bounded, and this bound SHOULD
    //# be SRTT.
    fn dsack_more_than_255_rounds_and_full_width_window_cap() {
        let mut rack = Rack::new().unwrap();
        let scoreboard = Scoreboard::new();
        rack.sample(4, 0);
        for round in 1..=400 {
            let ack = Seq(round * 1000);
            let high = ack.wrapping_add(1000);
            rack.acknowledge(ack, high, &scoreboard, 0, None, None, 1000, true);
            assert_eq!(rack.multiplier, u128::from(round) + 1);
            assert_eq!(
                rack.reo_window(false, Some(400)),
                u64::from(round + 1).min(400)
            );
            rack.acknowledge(ack, high, &scoreboard, 0, None, None, 1000, true);
            assert_eq!(rack.multiplier, u128::from(round) + 1);
        }
        for minimum in [1, 2, 3, 4, u64::MAX] {
            rack.min_rtt = Some(minimum);
            rack.multiplier = MAX_MULTIPLIER;
            assert_eq!(rack.reo_window(false, Some(u64::MAX)), u64::MAX);
            assert_eq!(rack.reo_window(true, Some(123)), 123);
            assert_eq!(rack.reo_window(false, None), 0);
            assert_eq!(rack.reo_window(false, Some(0)), 0);
        }
        rack.min_rtt = Some(3);
        rack.multiplier = 2;
        assert_eq!(rack.reo_window(false, Some(100)), 1);
        rack.multiplier = MAX_MULTIPLIER;
        rack.acknowledge(
            Seq(500_000),
            Seq(501_000),
            &scoreboard,
            0,
            None,
            None,
            1000,
            true,
        );
        assert_eq!(rack.multiplier, MAX_MULTIPLIER);
        for _ in 0..16 {
            rack.recovery_exit(false);
        }
        assert_eq!(rack.multiplier, 1);
    }

    #[test]
    fn lost_selection_keeps_packet_boundary_and_charges_redundant_suffix() {
        for base in [Seq(1), Seq(u32::MAX - 499)] {
            for prefix in [0, 123] {
                let seq = |n: u32| base.wrapping_add(n);
                let mut rack = Rack::new().unwrap();
                let mut scoreboard = Scoreboard::new();
                rack.sample(100, 0);
                rack.transmit(base, seq(1000), 0, false);
                rack.transmit(seq(1000), seq(2000), 0, false);
                rack.rto(200, base, Some(100));
                let blocks = [(seq(999).0, seq(2000).0), (base.0, seq(prefix).0)];
                let blocks = &blocks[..if prefix == 0 { 1 } else { 2 }];
                assert_eq!(
                    sack(&mut rack, &mut scoreboard, base.0, seq(2000).0, 300, blocks),
                    1001 + prefix
                );
                assert_eq!(rack.pipe(), 0);
                assert_eq!(rack.counts().sacked, 1);
                let advice = scoreboard.ranges().to_vec();
                // Large credit must not reach the wholly SACKed next packet.
                assert_eq!(rack.lowest_lost(2000), Some((seq(prefix), seq(1000))));
                // MSS or congestion credit clips even the redundant suffix.
                assert_eq!(
                    rack.lowest_lost(300),
                    Some((seq(prefix), seq(prefix + 300)))
                );
                let (start, end) = rack.lowest_lost(1000).unwrap();
                rack.transmit(start, end, 400, true);
                assert_eq!(rack.pipe(), 1000 - prefix);
                assert_eq!(rack.lowest_lost(1000), None);
                assert_eq!(scoreboard.ranges(), advice);
                assert_eq!(
                    sack(&mut rack, &mut scoreboard, base.0, seq(2000).0, 500, blocks),
                    0
                );
                assert_eq!(rack.pipe(), 999 - prefix);
                assert_eq!(
                    sack(
                        &mut rack,
                        &mut scoreboard,
                        seq(2000).0,
                        seq(2000).0,
                        600,
                        &[]
                    ),
                    999 - prefix
                );
                assert_eq!(rack.pipe(), 0);
                assert_eq!(rack.lowest_lost(1000), None);
            }
        }
    }

    #[test]
    fn lost_selection_never_extends_past_transmitted_high() {
        for base in [Seq(1), Seq(u32::MAX - 499)] {
            let end = base.wrapping_add(777);
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.transmit(base, end, 0, false);
            rack.rto(200, base, None);
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                end.0,
                300,
                &[(base.wrapping_add(776).0, end.0)],
            );
            assert_eq!(rack.lowest_lost(1000), Some((base, end)));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Retransmitting suffix marks untouched prefix ambiguous; immediate full SACK cannot create RTT/latest evidence.
    //# To avoid spurious inferences, ignore a segment as invalid if any of
    //# its sequence range has been retransmitted before and if either of two
    //# conditions is true:
    //#
    //# 1.  The Timestamp Echo Reply field (TSecr) of the ACK's timestamp
    //# option [RFC7323], if available, indicates the ACK was not
    //# acknowledging the last retransmission of the segment.
    //#
    //# 2.  The segment was last retransmitted less than RACK.min_rtt ago.
    fn clipped_retransmit_makes_untouched_original_prefix_rtt_ambiguous() {
        for base in [Seq(0), Seq(u32::MAX - 499)] {
            let end = base.wrapping_add(1000);
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.sample(100_000, 0);
            rack.transmit(base, end, 100_000, false);
            rack.transmit(base.wrapping_add(12), end, 300_000, true);
            assert!(!rack.intervals[0].retransmitted);
            assert!(rack.intervals[0].original_retransmitted);
            assert!(rack.intervals[1].retransmitted);
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    base.0,
                    end.0,
                    300_001,
                    &[(base.0, end.0)]
                ),
                1000
            );
            assert_eq!(rack.ack_sample, None);
            assert_eq!(rack.latest, None);
            assert_eq!(rack.min_rtt, Some(100_000));
            assert!(!rack.detect(300_001, false, Some(100_000)));
            assert_eq!(rack.deadline, None);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Checks SACK split, partial cumulative ACK, MSS-clipped tail and sequence wrap.
    //# If such an unsent segment is not available, then the sender SHOULD
    //# retransmit the highest-sequence segment sent so far and set
    //# TLP.is_retrans to true.
    fn tail_segment_retains_original_sack_boundaries_partial_ack_and_wrap() {
        for base in [Seq(1), Seq(u32::MAX - 499)] {
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            let end = base.wrapping_add(2000);
            rack.transmit(base, base.wrapping_add(1000), 0, false);
            rack.transmit(base.wrapping_add(1000), end, 0, false);
            sack(
                &mut rack,
                &mut scoreboard,
                base.0,
                end.0,
                10,
                &[(base.wrapping_add(1999).0, end.0)],
            );
            assert_eq!(
                rack.tail_segment(1000),
                Some((base.wrapping_add(1000), end))
            );
            sack(
                &mut rack,
                &mut scoreboard,
                base.wrapping_add(1500).0,
                end.0,
                20,
                &[],
            );
            assert_eq!(
                rack.tail_segment(1000),
                Some((base.wrapping_add(1500), end))
            );
            assert_eq!(rack.tail_segment(300), Some((base.wrapping_add(1700), end)));
            rack.abandon(end);
            assert_eq!(rack.tail_segment(1000), None);
        }
    }

    #[test]
    fn cumulative_reclamation_needs_no_split_capacity_or_advice() {
        for base in [Seq(10), Seq(u32::MAX - 5)] {
            let mut rack = Rack::with_capacity(3).unwrap();
            for i in 0..3 {
                rack.transmit(
                    base.wrapping_add(4 * i),
                    base.wrapping_add(4 * i + 4),
                    100 + u64::from(i),
                    false,
                );
            }
            rack.trim_cumulative(base.wrapping_add(2));
            assert!(rack.valid());
            assert_eq!(rack.intervals.len(), 3);
            assert_eq!(rack.intervals[0].start, base.wrapping_add(2));
            assert_eq!(
                original_packet(&rack, base.wrapping_add(2)),
                Some((base, base.wrapping_add(4), 100, false))
            );
            assert_eq!(rack.latest, None);
            assert_eq!(rack.ack_sample, None);
            rack.trim_cumulative(base.wrapping_add(4));
            rack.transmit(base.wrapping_add(12), base.wrapping_add(13), 200, false);
            assert!(rack.valid());
            assert_eq!(rack.intervals.len(), 3);
            assert_eq!(
                rack.head_transmission(base.wrapping_add(12)),
                Some((base.wrapping_add(13), 200))
            );
        }
    }

    #[test]
    fn abandoned_ledger_cumulative_reclamation_waits_for_extended_boundary() {
        let base = Seq(u32::MAX - 3);
        let mut rack = Rack::with_capacity(1).unwrap();
        rack.transmit(base, base.wrapping_add(2), 100, false);
        rack.transmit(base.wrapping_add(2), base.wrapping_add(4), 200, false);
        assert!(!rack.valid()); // Explicit defensive capacity exhaustion.
        rack.trim_cumulative(base.wrapping_add(2));
        assert!(!rack.valid());
        rack.transmit(base.wrapping_add(4), base.wrapping_add(5), 300, false);
        rack.trim_cumulative(base.wrapping_add(4));
        assert!(!rack.valid());
        rack.trim_cumulative(base.wrapping_add(5));
        assert!(rack.valid());
        rack.transmit(base.wrapping_add(5), base.wrapping_add(6), 400, false);
        assert_eq!(
            rack.head_transmission(base.wrapping_add(5)),
            Some((base.wrapping_add(6), 400))
        );
        assert_eq!(rack.latest, None);
    }

    #[test]
    fn interval_splits_wrap_unique_delivery_and_identity() {
        let base = u32::MAX - 1999;
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        for i in 0..3 {
            rack.transmit(
                Seq(base.wrapping_add(i * 1000)),
                Seq(base.wrapping_add((i + 1) * 1000)),
                0,
                false,
            );
        }
        let high = base.wrapping_add(3000);
        let block = [(base.wrapping_add(1111), base.wrapping_add(1555))];
        assert_eq!(
            sack(&mut rack, &mut scoreboard, base, high, 100, &block),
            444
        );
        assert_eq!(rack.counts().unacked, 3);
        assert_eq!(rack.counts().sacked, 0);
        assert_eq!(sack(&mut rack, &mut scoreboard, base, high, 101, &block), 0);
        assert_eq!(
            sack(
                &mut rack,
                &mut scoreboard,
                base.wrapping_add(1700),
                high,
                102,
                &[]
            ),
            1256
        );
        assert_eq!(rack.counts().unacked, 2);
        assert_eq!(rack.latest, Some((0, Seq(base.wrapping_add(1000)))));
        assert_eq!(rack.counts().sacked, 0);
        assert_eq!(sack(&mut rack, &mut scoreboard, high, high, 103, &[]), 1300);
        assert_eq!(rack.counts().unacked, 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Partial bytes cannot update minimum RTT; completing the transmission can.
    //# Use the RTT measurements obtained via [RFC6298] or [RFC7323] to
    //# update the estimated minimum RTT in RACK.min_RTT.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-5.1
    //= type=test
    //= reason=One-byte tail SACK does not advance RACK; completing the full original or retransmitted range does.
    //# Denotes the time when the full sequence range of RACK.segment was
    //# selectively or cumulatively acknowledged.
    fn partial_delivery_waits_for_complete_transmission_across_wrap() {
        for base in [0u32, u32::MAX - 1357] {
            let seq = |offset| base.wrapping_add(offset);
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            for i in 0..3 {
                rack.transmit(Seq(seq(i * 1000)), Seq(seq((i + 1) * 1000)), 10, false);
            }
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    seq(0),
                    seq(3000),
                    110,
                    &[(seq(2999), seq(3000))]
                ),
                1
            );
            assert_eq!(rack.latest, None);
            assert_eq!(rack.min_rtt, None);
            assert_eq!(rack.counts().sacked, 0);
            rack.detect(200, false, Some(100));
            assert_eq!(rack.lowest_lost(1000), None);
            assert_eq!(
                sack(
                    &mut rack,
                    &mut scoreboard,
                    seq(0),
                    seq(3000),
                    210,
                    &[(seq(2000), seq(3000))]
                ),
                999
            );
            assert_eq!(rack.latest, Some((10, Seq(seq(3000)))));
            assert_eq!(rack.min_rtt, Some(200));
            assert_eq!(rack.counts().sacked, 1);
            // Retransmission boundaries can cross original logical identities.
            rack.transmit(Seq(seq(500)), Seq(seq(1500)), 220, true);
            let latest = rack.latest;
            sack(
                &mut rack,
                &mut scoreboard,
                seq(0),
                seq(3000),
                420,
                &[(seq(1000), seq(1500))],
            );
            assert_eq!(rack.latest, latest);
            sack(
                &mut rack,
                &mut scoreboard,
                seq(0),
                seq(3000),
                421,
                &[(seq(500), seq(1500))],
            );
            assert_eq!(rack.latest, Some((220, Seq(seq(1500)))));
            assert_eq!(rack.counts().sacked, 1);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Asserts maximum deadline and timeout marking, then lost retransmission detection.
    //# For timely loss detection, it is RECOMMENDED that the
    //# sender install a reordering timer.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.2
    //= type=test
    //= reason=Detects loss of a retransmission and makes it selectable again.
    //# Therefore, the algorithm [RFC6675]
    //# MUST NOT be used with RACK-TLP; instead, a modified recovery
    //# algorithm that carefully addresses such a case is needed.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Retransmitted eligible packet advances reference used for lost-retransmission detection.
    //# Among all the segments newly ACKed or SACKed by this ACK that pass
    //# the checks above, update the RACK.rtt to be the RTT sample calculated
    //# using this ACK.  Furthermore, record the most recent Segment.xmit_ts
    //# in RACK.xmit_ts if it is ahead of RACK.xmit_ts.  If Segment.xmit_ts
    //# equals RACK.xmit_ts (e.g., due to clock granularity limits), then
    //# compare Segment.end_seq and RACK.end_seq to break the tie when
    //# deciding whether to update the RACK.segment's associated state.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks maximum remaining timer, original loss, retransmit reset and one-shot lost retransmission detection.
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
    fn maximum_timer_remaining_and_lost_retransmission() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        for (i, time) in [0, 10, 20].into_iter().enumerate() {
            rack.transmit(
                Seq(i as u32 * 1000),
                Seq((i as u32 + 1) * 1000),
                time,
                false,
            );
        }
        sack(&mut rack, &mut scoreboard, 0, 3000, 100, &[(2000, 3000)]);
        assert!(!rack.detect(100, false, Some(100)));
        assert_eq!(rack.deadline, Some(110));
        rack.detect(110, false, Some(100));
        assert_eq!(rack.counts().lost, 2);
        rack.transmit(Seq(0), Seq(1000), 125, true);
        rack.transmit(Seq(1000), Seq(2000), 126, true);
        assert_eq!((rack.counts().lost, rack.counts().retransmitted), (2, 2));
        sack(&mut rack, &mut scoreboard, 0, 3000, 226, &[(1000, 3000)]);
        assert!(rack.detect(226, true, Some(100)));
        assert_eq!(rack.lowest_lost(1000), Some((Seq(0), Seq(1000))));
        assert_eq!((rack.counts().lost, rack.counts().retransmitted), (1, 0));
        rack.transmit(Seq(0), Seq(1000), 227, true);
        assert_eq!((rack.counts().lost, rack.counts().retransmitted), (1, 1));
    }

    #[test]
    fn retransmission_copy_windows_survive_splits_and_renew_on_commit() {
        for base in [0, u32::MAX - 1999] {
            let seq = |offset| Seq(base).wrapping_add(offset);
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.sample(100, 0);
            for i in 0..4 {
                rack.transmit(seq(i * 1000), seq((i + 1) * 1000), 0, false);
                rack.transmit(seq(i * 1000), seq((i + 1) * 1000), 100 + u64::from(i), true);
            }
            sack(
                &mut rack,
                &mut scoreboard,
                base,
                seq(4000).0,
                201,
                &[(seq(1000).0, seq(2000).0)],
            );
            assert!(rack.detect(201, true, Some(100)));
            assert!(rack.intervals.iter().all(|r| !r.loss_response_pending));
            // A split of an accounted, still outstanding copy stays accounted.
            assert!(rack.split(seq(2500)));
            sack(
                &mut rack,
                &mut scoreboard,
                base,
                seq(4000).0,
                203,
                &[(seq(1000).0, seq(2000).0), (seq(3000).0, seq(4000).0)],
            );
            assert!(!rack.detect(203, true, Some(100))); // Older third copy, later ACK.
            assert!(
                rack.intervals
                    .iter()
                    .filter(|r| r.start == seq(2000) || r.start == seq(2500))
                    .all(|r| r.needs_retransmit && !r.loss_response_pending)
            );
            // Two successful replacements share the timestamp of the prior
            // detect call, but constitute new, unaccounted committed copies.
            rack.transmit(seq(0), seq(1000), 203, true);
            assert!(rack.split(seq(500)));
            assert!(
                rack.intervals
                    .iter()
                    .filter(|r| r.start == seq(0) || r.start == seq(500))
                    .all(|r| r.loss_response_pending)
            );
            rack.transmit(seq(2000), seq(3000), 203, true);
            sack(
                &mut rack,
                &mut scoreboard,
                base,
                seq(4000).0,
                303,
                &[(seq(1000).0, seq(4000).0)],
            );
            assert!(rack.detect(303, true, Some(100)));
            assert!(!rack.detect(303, true, Some(100))); // Response is one-shot.
            // Partial retransmission renews just its successfully sent range.
            rack.transmit(seq(0), seq(500), 303, true);
            assert!(rack.intervals[0].loss_response_pending);
            assert!(!rack.intervals[1].loss_response_pending);
        }
    }

    #[test]
    fn capacity_overflow_disables_inference_until_flight_is_acked() {
        for split_overflow in [false, true] {
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            for i in 0..CAPACITY as u32 {
                rack.transmit(Seq(i * 1000), Seq((i + 1) * 1000), 0, false);
            }
            let mut high = CAPACITY as u32 * 1000;
            if split_overflow {
                sack(&mut rack, &mut scoreboard, 0, high, 100, &[(1111, 1555)]);
            } else {
                rack.transmit(Seq(high), Seq(high + 1000), 1, false);
                high += 1000;
            }
            assert!(!rack.valid());
            assert!(rack.intervals.len() <= CAPACITY);
            assert_eq!(rack.lowest_lost(1000), None);
            rack.transmit(Seq(high), Seq(high + 1000), 2, false);
            sack(&mut rack, &mut scoreboard, high, high + 1000, 101, &[]);
            assert!(!rack.valid());
            sack(
                &mut rack,
                &mut scoreboard,
                high + 1000,
                high + 1000,
                102,
                &[],
            );
            assert!(rack.valid());
            rack.transmit(Seq(high + 1000), Seq(high + 2000), 103, false);
            assert_eq!(rack.counts().unacked, 1);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.3
    //= type=test
    //= reason=Asserts only first loss when another segment is recent and rejects early ACK of retransmission.
    //# Upon RTO timer expiration, RACK marks the first outstanding segment
    //# as lost (since it was sent an RTO ago); for all the other segments,
    //# RACK only marks the segment as lost if the time elapsed since the
    //# segment was transmitted is at least the sum of the recent RTT and the
    //# reordering window.
    fn rto_marks_first_and_age_eligible_only_and_karn_rejects_early_retx_ack() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        rack.transmit(Seq(0), Seq(1000), 0, false);
        rack.transmit(Seq(1000), Seq(2000), 999, false);
        rack.rto(1000, Seq(0), Some(100));
        assert_eq!(rack.counts().lost, 1);
        rack.transmit(Seq(0), Seq(1000), 1000, true);
        sack(&mut rack, &mut scoreboard, 1000, 2000, 1001, &[]);
        assert_eq!(rack.latest, None);
        assert_eq!(rack.ack_sample, None);
        assert_eq!(rack.counts().lost, 0);
        assert_eq!(rack.lowest_lost(1000), None);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= type=test
    //= reason=Checks original/retransmission timestamp storage and retransmitted state, not physical clock granularity.
    //# For each data segment sent, the sender MUST store its most recent
    //# transmission time with a timestamp whose granularity is finer
    //# than 1/4 of the minimum RTT of the connection.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.3
    //= type=test
    //= reason=Checks timestamp/lost flag reset for the shared transmit procedure.
    //# The sender MUST follow the RACK transmission procedures in the "Upon
    //# Transmitting a Data Segment" section upon sending either a
    //# retransmission or a new data loss probe.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.1
    //= type=test
    //= reason=Asserts committed timestamps, retransmitted flag, pending-loss reset and pipe restoration.
    //# Upon transmitting a new segment or retransmitting an old segment,
    //# record the time in Segment.xmit_ts and set Segment.lost to FALSE.
    //# Upon retransmitting a segment, set Segment.retransmitted to TRUE.
    fn transmission_commit_updates_timestamp_and_clears_pending_loss() {
        let mut rack = Rack::new().unwrap();
        rack.transmit(Seq(0), Seq(1000), 10, false);
        assert_eq!(rack.intervals[0].sent, 10);
        assert!(!rack.intervals[0].retransmitted);
        assert!(!rack.intervals[0].needs_retransmit);
        rack.rto(20, Seq(0), None);
        assert!(rack.intervals[0].needs_retransmit);
        assert_eq!(rack.pipe(), 0);
        rack.transmit(Seq(0), Seq(1000), 30, true);
        assert_eq!(rack.intervals[0].sent, 30);
        assert!(rack.intervals[0].retransmitted);
        assert!(!rack.intervals[0].needs_retransmit);
        assert_eq!(rack.pipe(), 1000);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Separately rejects too-fast retransmission ACK and nonmatching old echo, accepts matching echo at min RTT without feeding ordinary estimator.
    //# To avoid spurious inferences, ignore a segment as invalid if any of
    //# its sequence range has been retransmitted before and if either of two
    //# conditions is true:
    //#
    //# 1.  The Timestamp Echo Reply field (TSecr) of the ACK's timestamp
    //# option [RFC7323], if available, indicates the ACK was not
    //# acknowledging the last retransmission of the segment.
    //#
    //# 2.  The segment was last retransmitted less than RACK.min_rtt ago.
    // RACK retransmission feedback versus ordinary RTO sample.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= type=test
    //= reason=RACK retransmission feedback versus ordinary RTO sample.
    //# TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
    // RACK retransmission feedback versus ordinary RTO sample.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-3
    //= type=test
    //= reason=RACK retransmission feedback versus ordinary RTO sample.
    //# That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus
    //# for which it is ambiguous whether the reply was for the first instance of the packet
    //# or a later instance).
    fn retransmitted_ack_requires_min_rtt_and_matching_timestamp() {
        for (now, echo, valid) in [
            (399_999, 300, false), // Matching echo, but below minimum RTT.
            (400_000, 100, false), // Old original transmission echo.
            (400_000, 300, true),
        ] {
            let mut rack = Rack::new().unwrap();
            let scoreboard = Scoreboard::new();
            rack.sample(100_000, 0);
            rack.transmit(Seq(0), Seq(1000), 100_000, false);
            rack.transmit(Seq(0), Seq(1000), 300_000, true);
            assert_eq!(
                rack.acknowledge(
                    Seq(1000),
                    Seq(1000),
                    &scoreboard,
                    now,
                    Some(echo),
                    Some(TimestampGranularity::Milliseconds),
                    1000,
                    false,
                ),
                1000
            );
            assert_eq!(rack.latest, valid.then_some((300_000, Seq(1000))));
            assert_eq!(rack.ack_sample, None); // Karn exclusion, even when RACK qualifies.
            assert_eq!(rack.min_rtt, Some(100_000));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= type=test
    //= reason=Checks unknown RTT, fractional window, three-SACK threshold and recovery zeroing; observed original reordering disables zeroing.
    //# The reordering window SHOULD be set to zero if no reordering has
    //# been observed on the connection so far, and either (a) three
    //# segments have been SACKed since the last recovery or (b) the
    //# sender is already in fast or RTO recovery.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= type=test
    //= reason=Checks initial fractional and unavailable RTT windows.
    //# Otherwise, the
    //# reordering window SHOULD start from a small fraction of the
    //# round-trip time or zero if no round-trip time estimate is
    //# available.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks original reordered delivery versus retransmitted lower segment and its effect on window zeroing.
    //# If a never-retransmitted segment
    //# that's below RACK.fack is (selectively or cumulatively) acknowledged,
    //# it has been delivered out of order.  The sender sets
    //# RACK.reordering_seen to TRUE if such a segment is identified.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks a positive settling window remains after original reordering.
    //# Otherwise, if some reordering has been observed, then RACK does not
    //# trigger fast recovery based on DupThresh.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks initial and unknown windows, three-SACK zeroing, original reordering and recovery zeroing.
    //# If RACK.reordering_seen is FALSE:
    //# If in Fast or RTO recovery:
    //# Return 0
    //# Else if RACK.segs_sacked >= DupThresh:
    //# Return 0
    //# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
    fn original_reordering_and_zero_window_rules() {
        let mut unknown = Rack::new().unwrap();
        assert_eq!(unknown.reo_window(false, None), 0);
        unknown.sample(100, 0);
        assert_eq!(unknown.reo_window(false, Some(100)), 25);
        assert_eq!(unknown.reo_window(true, Some(100)), 0);
        for retransmit in [false, true] {
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.sample(100, 0);
            for i in 0..4 {
                rack.transmit(Seq(i * 1000), Seq((i + 1) * 1000), 0, false);
            }
            sack(&mut rack, &mut scoreboard, 0, 4000, 100, &[(1000, 4000)]);
            assert_eq!(rack.counts().sacked, 3);
            assert_eq!(rack.reo_window(false, Some(100)), 0);
            if retransmit {
                rack.transmit(Seq(0), Seq(1000), 110, true);
            }
            sack(&mut rack, &mut scoreboard, 1000, 4000, 210, &[]);
            assert_eq!(rack.reordering_seen, !retransmit);
            assert_eq!(
                rack.reo_window(false, Some(100)),
                if retransmit { 0 } else { 25 }
            );
            assert_eq!(
                rack.reo_window(true, Some(100)),
                if retransmit { 0 } else { 25 }
            );
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks equal-timestamp tie ordering and wrap, preserving latest while later ACK of older transmission updates RTT.
    //# Among all the segments newly ACKed or SACKed by this ACK that pass
    //# the checks above, update the RACK.rtt to be the RTT sample calculated
    //# using this ACK.  Furthermore, record the most recent Segment.xmit_ts
    //# in RACK.xmit_ts if it is ahead of RACK.xmit_ts.  If Segment.xmit_ts
    //# equals RACK.xmit_ts (e.g., due to clock granularity limits), then
    //# compare Segment.end_seq and RACK.end_seq to break the tie when
    //# deciding whether to update the RACK.segment's associated state.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks equal timestamp end-sequence ordering across wrap.
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
    fn equal_timestamp_tie_breaks_in_serial_sequence_space() {
        for base in [0u32, u32::MAX - 499] {
            let seq = |n| Seq(base.wrapping_add(n));
            let mut rack = Rack::new().unwrap();
            let mut scoreboard = Scoreboard::new();
            rack.transmit(seq(0), seq(1000), 10, false);
            rack.transmit(seq(1000), seq(2000), 10, false);
            sack(
                &mut rack,
                &mut scoreboard,
                base,
                seq(2000).0,
                110,
                &[(seq(1000).0, seq(2000).0)],
            );
            assert_eq!(rack.latest, Some((10, seq(2000))));
            rack.detect(134, false, Some(100));
            assert_eq!(rack.lowest_lost(1000), None);
            assert_eq!(rack.deadline, Some(135));
            rack.detect(135, false, Some(100));
            assert_eq!(rack.lowest_lost(1000), Some((seq(0), seq(1000))));
            // The older original can update the RTT but cannot regress the reference.
            sack(
                &mut rack,
                &mut scoreboard,
                seq(2000).0,
                seq(2000).0,
                210,
                &[],
            );
            assert_eq!(rack.latest, Some((10, seq(2000))));
            assert_eq!(rack.rtt, 200);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= type=test
    //= reason=Checks repeated DSACK in a round, advancement into a new round, SRTT cap and sixteen exits.
    //# The RACK reordering window SHOULD adaptively increase (using the
    //# algorithm in "Step 4: Update RACK reordering window" below) if
    //# the sender receives a Duplicate Selective Acknowledgment (DSACK)
    //# option [RFC2883].
    //= https://www.rfc-editor.org/rfc/rfc8985#section-3.3.2
    //= type=test
    //= reason=Exercises multiplier growth past the SRTT bound.
    //# The RACK reordering window MUST be bounded, and this bound SHOULD
    //# be SRTT.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= type=test
    //= reason=Checks round-bounded growth, cap and persistence.
    //# RACK DSACK-based reordering window adaptation is RECOMMENDED but
    //# is not required.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Covers repeated same-round DSACK, boundary advancement and SRTT cap.
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
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks helper persistence through 15 exits and reset at 16; does not cover RTO integration.
    //# Else if exiting Fast or RTO recovery:
    //# RACK.reo_wnd_persist -= 1
    //# If RACK.reo_wnd_persist <= 0:
    //# RACK.reo_wnd_mult = 1
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.2
    //= type=test
    //= reason=Checks DSACK growth, SRTT cap and persistence reset.
    //# If RACK.reordering_seen is FALSE:
    //# If in Fast or RTO recovery:
    //# Return 0
    //# Else if RACK.segs_sacked >= DupThresh:
    //# Return 0
    //# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
    fn dsack_new_round_cap_and_sixteen_recovery_decay() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        rack.transmit(Seq(1000), Seq(2000), 0, false);
        sack(&mut rack, &mut scoreboard, 1000, 2000, 100, &[(0, 1000)]);
        assert_eq!(rack.multiplier, 2);
        sack(&mut rack, &mut scoreboard, 1000, 2000, 101, &[(0, 1000)]);
        assert_eq!(rack.multiplier, 2);
        for high in [3000, 4000, 5000] {
            let ack = high - 1000;
            rack.transmit(Seq(ack), Seq(high), 102, false);
            sack(
                &mut rack,
                &mut scoreboard,
                ack,
                high,
                202,
                &[(ack - 1000, ack)],
            );
        }
        assert_eq!(rack.multiplier, 5);
        assert_eq!(rack.reo_window(false, Some(100)), 100); // Uncapped value is 125.
        for _ in 0..15 {
            rack.recovery_exit(false);
            assert_eq!(rack.multiplier, 5);
        }
        rack.recovery_exit(false);
        assert_eq!(rack.multiplier, 1);
        assert_eq!(rack.reo_window(false, Some(100)), 25);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.3
    //= type=test
    //= reason=Checks nonzero reordering window before/at age deadline and the first-outstanding exception.
    //# Upon RTO timer expiration, RACK marks the first outstanding segment
    //# as lost (since it was sent an RTO ago); for all the other segments,
    //# RACK only marks the segment as lost if the time elapsed since the
    //# segment was transmitted is at least the sum of the recent RTT and the
    //# reordering window.
    fn rto_nonzero_window_age_boundary_and_first_exception() {
        for now in [124, 125] {
            let mut rack = Rack::new().unwrap();
            rack.sample(100, 0);
            rack.reordering_seen = true;
            rack.transmit(Seq(0), Seq(1000), 124, false);
            rack.transmit(Seq(1000), Seq(2000), 0, false);
            rack.transmit(Seq(2000), Seq(3000), 100, false);
            assert_eq!(rack.reo_window(true, Some(100)), 25);
            rack.rto(now, Seq(0), Some(100));
            assert!(rack.intervals[0].needs_retransmit); // First: no age requirement.
            assert_eq!(rack.intervals[1].needs_retransmit, now == 125);
            assert!(!rack.intervals[2].needs_retransmit);
            assert_eq!(rack.deadline, None);
        }
    }

    #[test]
    fn dsack_is_not_delivery_and_growth_is_bounded_per_round() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100, 0);
        rack.transmit(Seq(1000), Seq(2000), 0, false);
        assert_eq!(
            sack(&mut rack, &mut scoreboard, 1000, 2000, 100, &[(0, 1000)]),
            0
        );
        assert_eq!(rack.reo_window(false, Some(100)), 50);
        sack(&mut rack, &mut scoreboard, 1000, 2000, 101, &[(0, 1000)]);
        assert_eq!(rack.reo_window(false, Some(100)), 50);
        for _ in 0..16 {
            rack.recovery_exit(false);
        }
        assert_eq!(rack.reo_window(false, Some(100)), 25);
    }
}

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
