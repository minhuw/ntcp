// Bounded transmission intervals shared by RACK selection and diagnostics.
// Sequence ranges are exclusive and always smaller than half the sequence space.
use crate::{sack::Scoreboard, seq::Seq};
use alloc::vec::Vec;
use core::cmp::Ordering;

const CAPACITY: usize = 256;

// Linux Documentation/networking/ip-sysctl.rst: tcp_min_rtt_wlen defaults
// to 300 seconds, balancing path migration against transient RTT inflation.
const MIN_RTT_WINDOW: u64 = 300_000_000;
const MIN_RTT_BUCKET: u64 = MIN_RTT_WINDOW / 3;
// Even a 1-us minimum can reach any u64 SRTT with this multiplier.
const MAX_MULTIPLIER: u128 = 4 * u64::MAX as u128;

#[derive(Clone, Copy, Debug)]
struct Interval {
    start: Seq,
    end: Seq,
    // Splits retain the original logical segment identity.
    original_end: Seq,
    transmission_start: Seq,
    transmission_end: Seq,
    sent: u64,
    retransmitted: bool,
    // Any retransmission of the original packet makes its untouched pieces
    // ambiguous too; their ACK may have been solicited by that retransmission.
    original_retransmitted: bool,
    // One-shot byte delivery attribution is independent of transmission state.
    delivered: bool,
    sacked: bool,
    original_lost: bool,
    needs_retransmit: bool,
    // This committed retransmission copy has not shared an extra loss response.
    // Splits copy the marker; only successful retransmit commits renew it.
    loss_response_pending: bool,
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
    intervals: Vec<Interval>,
    fallback: Option<Seq>,
    latest: Option<(u64, Seq)>,
    fack: Option<Seq>,
    min_rtt: Option<u64>,
    min_rtt_buckets: [Option<(u64, u64)>; 4],
    rtt: u64,
    reordering_seen: bool,
    pub(crate) reordering: u32,
    multiplier: u128,
    persist: u8,
    pub(crate) reo_grew: bool,
    dsack_round: Option<Seq>,
    pub(crate) deadline: Option<u64>,
    pub(crate) ack_sample: Option<u64>,
}

fn after(a: Seq, b: Seq) -> bool {
    a.serial_cmp(b) == Some(Ordering::Greater)
}
fn sent_after(a: (u64, Seq), b: (u64, Seq)) -> bool {
    a.0 > b.0 || a.0 == b.0 && after(a.1, b.1)
}

impl Rack {
    pub(crate) fn new() -> Result<Self, ()> {
        let mut intervals = Vec::new();
        intervals.try_reserve_exact(CAPACITY).map_err(|_| ())?;
        Ok(Self {
            intervals,
            fallback: None,
            latest: None,
            fack: None,
            min_rtt: None,
            min_rtt_buckets: [None; 4],
            rtt: 0,
            reordering_seen: false,
            reordering: 3,
            multiplier: 1,
            persist: 0,
            reo_grew: false,
            dsack_round: None,
            deadline: None,
            ack_sample: None,
        })
    }

    pub(crate) fn valid(&self) -> bool {
        self.fallback.is_none()
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
        // now is caller-supplied monotonic microseconds, as for acknowledge.
        // ponytail: bucket minima retain samples for 300..400 seconds, giving
        // a conservative (never higher) estimate of the exact 300-second min;
        // use a full sample deque only if exact expiration becomes necessary.
        // Like Linux tcp_update_rtt_min, aging happens on accepted samples,
        // not on timers: idle time alone does not erase the ambiguity guard.
        let epoch = now / MIN_RTT_BUCKET;
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

    pub(crate) fn abandon(&mut self, boundary: Seq) {
        self.intervals.clear();
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
        if self.intervals.len() == CAPACITY {
            return false;
        }
        let mut right = self.intervals[i];
        right.start = edge;
        self.intervals[i].end = edge;
        self.intervals.insert(i + 1, right);
        true
    }

    // Called only after encoding succeeds. Overflow disables time-based inference
    // until the entire incompletely represented flight is cumulatively ACKed.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-4
    //= reason=Partial evidence: every represented committed transmission stores the caller microsecond timestamp, including retransmissions.
    //# For each data segment sent, the sender MUST store its most recent
    //# transmission time with a timestamp whose granularity is finer
    //# than 1/4 of the minimum RTT of the connection.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-6.1
    //= reason=Original commit stores timestamp and clear pending loss; retransmit changes timestamp, sets retransmitted, clears needs_retransmit. original_lost is historical diagnostic state, not Segment.lost.
    //# Upon transmitting a new segment or retransmitting an old segment,
    //# record the time in Segment.xmit_ts and set Segment.lost to FALSE.
    //# Upon retransmitting a segment, set Segment.retransmitted to TRUE.
    pub(crate) fn transmit(&mut self, start: Seq, end: Seq, now: u64, retransmit: bool) {
        if let Some(boundary) = self.fallback {
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
            for segment in self
                .intervals
                .chunk_by_mut(|a, b| a.original_end == b.original_end)
            {
                if segment
                    .iter()
                    .any(|r| after(end, r.start) && after(r.end, start))
                {
                    for r in segment {
                        r.original_retransmitted = true;
                    }
                }
            }
            for r in &mut self.intervals {
                if !after(start, r.start) && !after(r.end, end) {
                    r.transmission_start = start;
                    r.transmission_end = end;
                    r.sent = now;
                    r.retransmitted = true;
                    r.loss_response_pending = true;
                    r.needs_retransmit = false;
                    r.sacked = false;
                }
            }
        } else if self.intervals.len() < CAPACITY {
            self.intervals.push(Interval {
                start,
                end,
                original_end: end,
                transmission_start: start,
                transmission_end: end,
                sent: now,
                retransmitted: false,
                original_retransmitted: false,
                delivered: false,
                sacked: false,
                original_lost: false,
                needs_retransmit: false,
                loss_response_pending: false,
            });
        } else {
            self.abandon(end);
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
    //= reason=Ambiguous original pieces cannot qualify; retransmitted range requires full coverage, RTT >= minimum and matching millisecond TSecr when timestamps negotiated. Equality check is stricter than merely rejecting old echoes.
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
    pub(crate) fn acknowledge(
        &mut self,
        ack: Seq,
        high: Seq,
        scoreboard: &Scoreboard,
        now: u64,
        echo: Option<u32>,
        timestamps: bool,
        mss: u32,
        dsack: bool,
    ) -> u32 {
        self.ack_sample = None;
        self.reo_grew = false;
        if let Some(boundary) = self.fallback {
            if !after(boundary, ack) {
                self.fallback = None;
                self.fack = Some(ack);
            }
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
        for r in &mut self.intervals {
            let cumulative = !after(r.end, ack);
            let covered = cumulative || scoreboard.unsacked_bytes(r.start, r.end) == 0;
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
                }
                if self.fack.is_none_or(|old| after(r.end, old)) {
                    self.fack = Some(r.end);
                }
                let rtt = now.saturating_sub(r.sent);
                let complete = !after(r.transmission_end, ack)
                    || scoreboard.unsacked_bytes(
                        if after(r.transmission_start, ack) {
                            r.transmission_start
                        } else {
                            ack
                        },
                        r.transmission_end,
                    ) == 0;
                let eligible = complete
                    && (r.retransmitted || !r.original_retransmitted)
                    && (!r.retransmitted
                        || (rtt >= self.min_rtt.unwrap_or(u64::MAX)
                            && (!timestamps || echo == Some((r.sent / 1000) as u32))));
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
    //= reason=Implements zeroing after three complete SACKed logical segments or in recovery only without observed reordering; otherwise multiplies before integer division by four and caps at SRTT. Missing estimates yield zero.
    //# If RACK.reordering_seen is FALSE:
    //# If in Fast or RTO recovery:
    //# Return 0
    //# Else if RACK.segs_sacked >= DupThresh:
    //# Return 0
    //# Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)
    fn reo_window(&self, recovery: bool, srtt: Option<u64>) -> u64 {
        if !self.reordering_seen && (recovery || self.counts().sacked >= 3) {
            return 0;
        }
        // Divide after multiplication, including minima below four us.
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
            }
        }
    }

    pub(crate) fn mark_scoreboard_losses(&mut self, scoreboard: &Scoreboard, mss: u32) {
        for r in &mut self.intervals {
            if !r.sacked && !r.retransmitted && scoreboard.is_lost(r.start, mss) {
                r.original_lost = true;
                r.needs_retransmit = true;
            }
        }
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
            .take_while(|r| r.original_end == tail.original_end)
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
        let size = first.original_end.distance_from(first.start).min(mss);
        Some((first.start, first.start.wrapping_add(size)))
    }

    pub(crate) fn pipe(&self) -> u32 {
        self.intervals
            .iter()
            .filter(|r| !r.sacked && !r.needs_retransmit)
            .map(|r| r.end.distance_from(r.start))
            .sum()
    }

    pub(crate) fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for segment in self
            .intervals
            .chunk_by(|a, b| a.original_end == b.original_end)
        {
            counts.unacked += 1;
            counts.sacked += u32::from(segment.iter().all(|r| r.sacked));
            counts.lost += u32::from(segment.iter().any(|r| r.original_lost && !r.sacked));
            counts.retransmitted += u32::from(
                segment
                    .iter()
                    .any(|r| r.retransmitted && !r.sacked && !r.needs_retransmit),
            );
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            false,
            1000,
            update.dsack,
        )
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
            rack.acknowledge(ack, high, &scoreboard, 0, None, false, 1000, true);
            assert_eq!(rack.multiplier, u128::from(round) + 1);
            assert_eq!(
                rack.reo_window(false, Some(400)),
                u64::from(round + 1).min(400)
            );
            rack.acknowledge(ack, high, &scoreboard, 0, None, false, 1000, true);
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
            false,
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
                    true,
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
