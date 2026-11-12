// Test oracle: the interval ledger as it was before the per-ACK and
// per-departure walks were indexed (master 39e49af), every operation a
// walk over all intervals. Randomized tests drive it and Rack with the same
// operations and compare every result and the intervals themselves.
use super::{
    Counts, DELIVERY_END, DIAGNOSTIC_LOST, DIAGNOSTIC_RETRY, DepartureSelection, Interval,
    MAX_MULTIPLIER, MIN_RTT_BUCKET, OriginalRetrySpan, PACKET_DELIVERED, PACKET_INCLUDES_FIN,
    RetryUndo, SYN_PAYLOAD, sent_after,
};
use crate::{
    connection::{CallerTimebase, TimestampGranularity},
    sack::Scoreboard,
    seq::Seq,
};
use alloc::vec::Vec;

// The old block storage behaved as a Vec bounded by its capacity.
#[derive(Debug)]
pub(super) struct Intervals(Vec<Interval>);

impl Intervals {
    fn new(capacity: usize) -> Result<Self, ()> {
        Ok(Self(Vec::with_capacity(capacity)))
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(super) fn iter(&self) -> core::slice::Iter<'_, Interval> {
        self.0.iter()
    }
    fn iter_mut(&mut self) -> core::slice::IterMut<'_, Interval> {
        self.0.iter_mut()
    }
    fn range(&self, start: usize, end: usize) -> core::slice::Iter<'_, Interval> {
        self.0[start..end].iter()
    }
    fn range_mut(&mut self, start: usize, end: usize) -> core::slice::IterMut<'_, Interval> {
        self.0[start..end].iter_mut()
    }
    fn first(&self) -> Option<&Interval> {
        self.0.first()
    }
    fn last(&self) -> Option<&Interval> {
        self.0.last()
    }
    fn push(&mut self, value: Interval) {
        self.0.push(value);
    }
    fn insert(&mut self, index: usize, value: Interval) {
        self.0.insert(index, value);
    }
    fn retain(&mut self, keep: impl FnMut(&Interval) -> bool) {
        self.0.retain(keep);
    }
    fn retain_mut(&mut self, keep: impl FnMut(&mut Interval) -> bool) {
        self.0.retain_mut(keep);
    }
    fn clear(&mut self) {
        self.0.clear();
    }
}
impl core::ops::Index<usize> for Intervals {
    type Output = Interval;
    fn index(&self, index: usize) -> &Interval {
        &self.0[index]
    }
}
impl core::ops::IndexMut<usize> for Intervals {
    fn index_mut(&mut self, index: usize) -> &mut Interval {
        &mut self.0[index]
    }
}
impl<'a> IntoIterator for &'a mut Intervals {
    type Item = &'a mut Interval;
    type IntoIter = core::slice::IterMut<'a, Interval>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

#[derive(Debug)]
pub(super) struct Reference {
    pub(super) intervals: Intervals,
    pub(super) capacity: usize,
    pub(super) selection_generation: u64,
    pub(super) departure_selection: Option<DepartureSelection>,
    pub(super) timebase: CallerTimebase,
    pub(super) sample_floor: u64,
    pub(super) fallback: Option<Seq>,
    pub(super) latest: Option<(u64, Seq)>,
    pub(super) fack: Option<Seq>,
    pub(super) min_rtt: Option<u64>,
    pub(super) min_rtt_buckets: [Option<(u64, u64)>; 4],
    pub(super) rtt: u64,
    pub(super) reordering_seen: bool,
    pub(super) reordering: u32,
    pub(super) reordering_events: u64,
    pub(super) multiplier: u128,
    pub(super) persist: u8,
    pub(super) reo_grew: bool,
    pub(super) dsack_round: Option<Seq>,
    pub(super) deadline: Option<u64>,
    pub(super) ack_sample: Option<u64>,
    pub(super) delivered_segments: u64,
    pub(super) delivered_segments_valid: bool,
}

impl Reference {
    pub(super) fn with_capacity(capacity: usize) -> Result<Self, ()> {
        Self::with_timebase(capacity, CallerTimebase::default())
    }

    pub(super) fn with_timebase(capacity: usize, timebase: CallerTimebase) -> Result<Self, ()> {
        let intervals = Intervals::new(capacity)?;
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

    pub(super) fn original_retry_span(
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

    pub(super) fn commit_original_window(&mut self, start: Seq, end: Seq, in_window: bool) {
        for r in &mut self.intervals {
            if r.original_start == start && r.original_end == end {
                r.originally_in_window = in_window;
            }
        }
    }

    pub(super) fn commit_retry_span(&mut self, start: Seq, end: Seq) {
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

    pub(super) fn head_transmission(&self, start: Seq) -> Option<(Seq, u64)> {
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

    pub(super) fn latest_delivered(&self) -> Option<u64> {
        self.latest.map(|(sent, _)| sent)
    }

    pub(super) fn valid(&self) -> bool {
        self.fallback.is_none()
    }

    pub(super) fn min_rtt(&self) -> Option<u64> {
        self.min_rtt
    }

    pub(super) fn sample(&mut self, rtt: u64, now: u64) {
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

    pub(super) fn discard_samples_before(&mut self, now: u64) {
        self.sample_floor = now;
    }

    pub(super) fn trim_cumulative(&mut self, ack: Seq) {
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

    pub(super) fn abandon(&mut self, boundary: Seq) {
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

    pub(super) fn retry_undo(&self, start: Seq, end: Seq) -> Option<RetryUndo> {
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

    pub(super) fn cancel_retry(&mut self, selection: DepartureSelection, undo: RetryUndo) -> bool {
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

    pub(super) fn departure_selection(&self) -> Option<DepartureSelection> {
        self.departure_selection.filter(|_| self.valid())
    }

    pub(super) fn validate_departure(
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

    pub(super) fn validate_departure_group(
        &self,
        selection: DepartureSelection,
        start: Seq,
        size: u32,
        bytes: usize,
        now: u64,
    ) -> bool {
        if size == 0 || bytes == 0 || bytes >= 1 << 31 {
            return false;
        }
        if !self.validate_departure(selection, start, start.wrapping_add(bytes as u32), now) {
            return false;
        }
        let segments = bytes.div_ceil(size as usize);
        let splits = (0..=segments)
            .filter(|&i| {
                let edge = start.wrapping_add((i * size as usize).min(bytes) as u32);
                self.intervals
                    .iter()
                    .any(|r| edge.after(r.start) && r.end.after(edge))
            })
            .count();
        splits <= self.capacity.saturating_sub(self.intervals.len())
    }

    pub(super) fn commit_departure(
        &mut self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) -> bool {
        if !self.validate_departure(selection, start, end, now) {
            return false;
        }
        self.commit_validated_departure(selection, start, end, now);
        true
    }

    pub(super) fn commit_validated_departure(
        &mut self,
        selection: DepartureSelection,
        start: Seq,
        end: Seq,
        now: u64,
    ) {
        debug_assert!(self.validate_departure(selection, start, end, now));
        let left = self.split(start);
        let right = self.split(end);
        debug_assert!(left && right);
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
    }

    pub(super) fn transmit(&mut self, start: Seq, end: Seq, now: u64, retransmit: bool) {
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

    pub(super) fn record_fin_payload(&mut self, start: Seq, end: Seq) -> bool {
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

    pub(super) fn record_syn_payload(&mut self, start: Seq, end: Seq) {
        for r in &mut self.intervals {
            if !start.after(r.start) && !r.end.after(end) {
                r.set_stats_flag(SYN_PAYLOAD, true);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn acknowledge(
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

    pub(super) fn recovery_exit(&mut self, grew: bool) {
        if grew {
            return;
        }
        self.persist = self.persist.saturating_sub(1);
        if self.persist == 0 {
            self.multiplier = 1;
        }
    }

    pub(super) fn adaptation(&self) -> (u128, u8) {
        (self.multiplier, self.persist)
    }

    fn reo_window(&self, recovery: bool, srtt: Option<u64>) -> u64 {
        if !self.reordering_seen && (recovery || self.packet_counts().sacked >= 3) {
            return 0;
        }
        ((u128::from(self.min_rtt.unwrap_or(0)).saturating_mul(self.multiplier) / 4)
            .min(u128::from(srtt.unwrap_or(0)))) as u64
    }

    pub(super) fn detect(&mut self, now: u64, recovery: bool, srtt: Option<u64>) -> bool {
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
            for r in &mut self.intervals {
                r.loss_response_pending = false;
            }
        }
        retransmission_lost
    }

    pub(super) fn rto(&mut self, now: u64, ack: Seq, srtt: Option<u64>) {
        let window = self.reo_window(true, srtt);
        self.deadline = None;
        for r in &mut self.intervals {
            r.sacked = false;
            r.delivered = false;
            if r.start == ack || now >= r.sent.saturating_add(self.rtt).saturating_add(window) {
                r.original_lost = true;
                r.needs_retransmit = true;
                r.set_stats_flag(DIAGNOSTIC_LOST, true);
            }
        }
    }

    pub(super) fn mark_head_lost(&mut self) {
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

    pub(super) fn mark_scoreboard_losses(&mut self, scoreboard: &Scoreboard, mss: u32) -> bool {
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

    pub(super) fn tail_segment(&self, mss: u32) -> Option<(Seq, Seq)> {
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

    pub(super) fn lowest_lost(&self, mss: u32) -> Option<(Seq, Seq)> {
        let first = self
            .intervals
            .iter()
            .find(|r| !r.sacked && r.needs_retransmit)?;
        let size = first.original_wire_end.distance_from(first.start).min(mss);
        Some((first.start, first.start.wrapping_add(size)))
    }

    pub(super) fn pipe(&self) -> u32 {
        self.intervals
            .iter()
            .filter(|r| !r.sacked && !r.needs_retransmit)
            .map(|r| r.end.distance_from(r.start))
            .sum()
    }

    pub(super) fn lost_ranges(
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

    pub(super) fn has_short_transmission(&self, mss: u32) -> bool {
        self.intervals
            .iter()
            .any(|r| r.transmission_end.distance_from(r.transmission_start) < mss)
    }

    pub(super) fn empty_valid(&self) -> bool {
        self.valid() && self.intervals.is_empty()
    }

    pub(super) fn cancel_unsubmitted_fresh(&mut self, selection: DepartureSelection) -> bool {
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

    pub(super) fn counts(&self) -> Counts {
        self.count_by_original(false)
    }

    pub(super) fn diagnostic_packet_counts(&self) -> Counts {
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

    pub(super) fn packet_counts(&self) -> Counts {
        self.count_by_original(true)
    }

    fn count_by_original(&self, physical: bool) -> Counts {
        let mut counts = Counts::default();
        let mut intervals = self.intervals.iter().peekable();
        while let Some(first) = intervals.next() {
            let mut sacked = first.sacked;
            let mut lost = first.original_lost && !first.sacked;
            let mut retransmitted = first.retransmitted && !first.sacked && !first.needs_retransmit;
            while let Some(next) = intervals.peek() {
                let same = if physical {
                    first.original_wire_start == next.original_wire_start
                        && first.original_wire_end == next.original_wire_end
                } else {
                    first.original_end == next.original_end
                };
                if !same {
                    break;
                }
                let next = intervals.next().unwrap();
                sacked &= next.sacked;
                lost |= next.original_lost && !next.sacked;
                retransmitted |= next.retransmitted && !next.sacked && !next.needs_retransmit;
            }
            counts.unacked += 1;
            counts.sacked += u32::from(sacked);
            counts.lost += u32::from(lost);
            counts.retransmitted += u32::from(retransmitted);
        }
        counts
    }
}
