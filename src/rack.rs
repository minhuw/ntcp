// Bounded transmission intervals shared by RACK selection and diagnostics.
// Sequence ranges are exclusive and always smaller than half the sequence space.
use crate::{sack::Scoreboard, seq::Seq};
use alloc::vec::Vec;
use core::cmp::Ordering;

const CAPACITY: usize = 256;

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
    sacked: bool,
    original_lost: bool,
    needs_retransmit: bool,
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
    rtt: u64,
    reordering_seen: bool,
    pub(crate) reordering: u32,
    multiplier: u8,
    persist: u8,
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
            rtt: 0,
            reordering_seen: false,
            reordering: 3,
            multiplier: 1,
            persist: 0,
            dsack_round: None,
            deadline: None,
            ack_sample: None,
        })
    }

    pub(crate) fn valid(&self) -> bool {
        self.fallback.is_none()
    }

    pub(crate) fn sample(&mut self, rtt: u64) {
        // ponytail: lifetime minimum; a windowed min filter is needed for path migration.
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |old| old.min(rtt)));
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
            for r in &mut self.intervals {
                if !after(start, r.start) && !after(r.end, end) {
                    r.transmission_start = start;
                    r.transmission_end = end;
                    r.sent = now;
                    r.retransmitted = true;
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
                sacked: false,
                original_lost: false,
                needs_retransmit: false,
            });
        } else {
            self.abandon(end);
        }
    }

    // Scoreboard is authoritative. Split at its byte edges, never scan send-buffer bytes.
    // Return newly delivered bytes, counting SACK-to-cumulative transitions only once.
    #[allow(clippy::too_many_arguments)]
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
                delivered += r.end.distance_from(r.start);
                if !r.retransmitted
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
                self.sample(rtt);
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
            self.multiplier = self.multiplier.saturating_add(1);
            self.persist = 16;
            self.reordering_seen = true;
        }
        delivered
    }

    pub(crate) fn recovery_exit(&mut self) {
        self.persist = self.persist.saturating_sub(1);
        if self.persist == 0 {
            self.multiplier = 1;
        }
    }

    fn reo_window(&self, recovery: bool, srtt: Option<u64>) -> u64 {
        if !self.reordering_seen && (recovery || self.counts().sacked >= 3) {
            return 0;
        }
        (self.min_rtt.unwrap_or(0) / 4)
            .saturating_mul(u64::from(self.multiplier))
            .min(srtt.unwrap_or(0))
    }

    // RFC 8985 §6.2: maximum remaining eligible interval, not minimum.
    // Return whether a retransmission itself was newly lost (new congestion).
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
                retransmission_lost |= r.retransmitted;
                r.original_lost = true;
                r.needs_retransmit = true;
            } else {
                self.deadline = Some(self.deadline.map_or(deadline, |old| old.max(deadline)));
            }
        }
        retransmission_lost
    }

    pub(crate) fn rto(&mut self, now: u64, ack: Seq, srtt: Option<u64>) {
        let window = self.reo_window(true, srtt);
        self.deadline = None;
        for r in &mut self.intervals {
            r.sacked = false;
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

    pub(crate) fn lowest_lost(&self, mss: u32) -> Option<(Seq, Seq)> {
        let i = self
            .intervals
            .iter()
            .position(|r| !r.sacked && r.needs_retransmit)?;
        let start = self.intervals[i].start;
        let mut end = start;
        for r in &self.intervals[i..] {
            if r.start != end || r.sacked || !r.needs_retransmit {
                break;
            }
            end = r.end;
            if end.distance_from(start) >= mss {
                return Some((start, start.wrapping_add(mss)));
            }
        }
        Some((start, end))
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
    fn maximum_timer_remaining_and_lost_retransmission() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100);
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
    fn rto_marks_first_and_age_eligible_only_and_karn_rejects_early_retx_ack() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100);
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
    fn dsack_is_not_delivery_and_growth_is_bounded_per_round() {
        let mut rack = Rack::new().unwrap();
        let mut scoreboard = Scoreboard::new();
        rack.sample(100);
        rack.transmit(Seq(1000), Seq(2000), 0, false);
        assert_eq!(
            sack(&mut rack, &mut scoreboard, 1000, 2000, 100, &[(0, 1000)]),
            0
        );
        assert_eq!(rack.reo_window(false, Some(100)), 50);
        sack(&mut rack, &mut scoreboard, 1000, 2000, 101, &[(0, 1000)]);
        assert_eq!(rack.reo_window(false, Some(100)), 50);
        for _ in 0..16 {
            rack.recovery_exit();
        }
        assert_eq!(rack.reo_window(false, Some(100)), 25);
    }
}
