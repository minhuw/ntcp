use core::cmp::Ordering;

use crate::seq::Seq;

const MIN_RTO: u64 = 1_000_000;
const MAX_RTO: u64 = 60_000_000;
const MAX_WINDOW: u32 = 0x7fff_ffff;

#[derive(Clone, Debug)]
pub(crate) struct RttEstimator {
    srtt: Option<u64>,
    variance: u64,
    rto: u64,
}

// Partial evidence: estimator arithmetic and bounded backoff only. The connection selects
// unambiguous samples (Karn), manages timers, and retransmits; this helper alone does not
// establish RFC 6298 conformance.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
//# The RTO MUST be computed according to the algorithm in [10], including Karn's algorithm
//# for taking RTT samples (MUST-18).
impl RttEstimator {
    pub(crate) fn new() -> Self {
        Self {
            srtt: None,
            variance: 0,
            rto: MIN_RTO,
        }
    }

    pub(crate) fn rto(&self) -> u64 {
        self.rto
    }

    // The caller excludes ambiguous retransmission samples (Karn's algorithm).
    pub(crate) fn sample(&mut self, rtt_us: u64) {
        let srtt = match self.srtt {
            None => {
                self.variance = rtt_us / 2;
                rtt_us
            }
            Some(old) => {
                // Widen before averaging: even u64::MAX samples remain accurate.
                self.variance =
                    ((3 * self.variance as u128 + old.abs_diff(rtt_us) as u128) / 4) as u64;
                ((7 * old as u128 + rtt_us as u128) / 8) as u64
            }
        };
        self.srtt = Some(srtt);
        self.rto = srtt
            .saturating_add(self.variance.saturating_mul(4).max(1_000))
            .clamp(MIN_RTO, MAX_RTO);
    }

    // Partial evidence: exponential RTO backoff only; congestion-window algorithms are in
    // Congestion and timer orchestration is in the connection.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //# A TCP endpoint MUST implement the basic congestion control algorithms slow start,
    //# congestion avoidance, and exponential backoff of RTO to avoid creating congestion
    //# collapse conditions (MUST-19).
    pub(crate) fn backoff(&mut self) {
        self.rto = self.rto.saturating_mul(2).min(MAX_RTO);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Congestion {
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    acknowledged: u64,
    duplicate_acks: u8,
    // Exclusive SND.NXT, not the inclusive highest byte used in RFC 6582.
    recover: Option<Seq>,
    fast_recovery: bool,
    ecn_end: Option<Seq>,
    timeout_retransmitted: bool,
    // Exclusive end of successfully emitted, still-unacknowledged retransmissions.
    retransmitted_end: Option<Seq>,
}

impl Congestion {
    pub(crate) fn new(mss: u32) -> Self {
        assert!(mss > 0);
        let mss = mss.min(MAX_WINDOW);
        Self {
            mss,
            cwnd: Self::initial_window(mss),
            ssthresh: MAX_WINDOW,
            acknowledged: 0,
            duplicate_acks: 0,
            recover: None,
            fast_recovery: false,
            ecn_end: None,
            timeout_retransmitted: false,
            retransmitted_end: None,
        }
    }

    fn initial_window(mss: u32) -> u32 {
        mss.saturating_mul(4)
            .min(mss.saturating_mul(2).max(4_380))
            .min(MAX_WINDOW)
    }

    pub(crate) fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[cfg(test)]
    pub(crate) fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    pub(crate) fn set_mss(&mut self, mss: u32) {
        assert!(mss > 0);
        let mss = mss.min(MAX_WINDOW);
        if mss < self.mss {
            // RFC 5681: preserve the segment count when the path MSS falls.
            self.cwnd = ((self.cwnd as u64 * mss as u64) / self.mss as u64) as u32;
        }
        self.mss = mss;
        self.cwnd = self.cwnd.max(mss).min(MAX_WINDOW);
        self.ssthresh = self.ssthresh.max(mss.saturating_mul(2)).min(MAX_WINDOW);
        self.acknowledged = 0;
    }

    #[cfg(test)]
    pub(crate) fn on_ack(&mut self, ack: Seq, acked: u32, flight_after_ack: u32) -> bool {
        self.on_ack_with_ecn(ack, acked, flight_after_ack, false)
    }

    // Call only for advancing cumulative ACKs; acked counts new data bytes.
    // True requests retransmission of the first unacknowledged segment.
    // Partial evidence: slow start and congestion avoidance on validated new ACKs. Flight
    // accounting, send-window enforcement, and RTO orchestration are caller
    // responsibilities; not a complete external-RFC audit.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //# A TCP endpoint MUST implement the basic congestion control algorithms slow start,
    //# congestion avoidance, and exponential backoff of RTO to avoid creating congestion
    //# collapse conditions (MUST-19).
    pub(crate) fn on_ack_with_ecn(
        &mut self,
        ack: Seq,
        acked: u32,
        flight_after_ack: u32,
        ece: bool,
    ) -> bool {
        if self.retransmitted_end.is_some_and(|end| {
            matches!(
                ack.serial_cmp(end),
                Some(Ordering::Equal | Ordering::Greater)
            )
        }) {
            self.retransmitted_end = None;
        }
        if acked == 0 {
            return false;
        }
        self.reset_duplicate_acks();
        self.timeout_retransmitted = false;
        let relation = self.recover.and_then(|recover| ack.serial_cmp(recover));
        if relation == Some(Ordering::Greater) {
            // Equality completes recovery, but does not permit a new reduction.
            self.recover = None;
        }
        if self.fast_recovery {
            if matches!(relation, Some(Ordering::Equal | Ordering::Greater)) {
                // RFC 6582 option (1) limits the burst after a full ACK.
                self.cwnd = self.ssthresh.min(
                    flight_after_ack
                        .max(self.mss)
                        .saturating_add(self.mss)
                        .min(MAX_WINDOW),
                );
                self.fast_recovery = false;
                self.acknowledged = 0;
                return false;
            }
            if relation == Some(Ordering::Less) {
                self.cwnd = self
                    .cwnd
                    .saturating_sub(acked)
                    .saturating_add(if acked >= self.mss { self.mss } else { 0 })
                    .clamp(self.mss, MAX_WINDOW);
                return true;
            }
            return false; // Half-space comparisons are not valid TCP ACKs.
        }
        if self
            .ecn_end
            .is_some_and(|end| ack.serial_cmp(end) == Some(Ordering::Greater))
        {
            self.ecn_end = None;
        }
        if ece {
            return false;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self
                .cwnd
                .saturating_add(acked.min(self.mss))
                .min(MAX_WINDOW);
        } else {
            self.acknowledged += acked as u64;
            if self.acknowledged >= self.cwnd as u64 {
                // At most one MSS per window of newly acknowledged bytes.
                self.acknowledged = 0;
                self.cwnd = self.cwnd.saturating_add(self.mss).min(MAX_WINDOW);
            }
        }
        false
    }

    // The caller checks RFC 5681's duplicate-ACK eligibility conditions.
    pub(crate) fn on_duplicate_ack(&mut self, flight: u32, highest_sent: Seq) -> bool {
        if self.fast_recovery {
            self.cwnd = self.cwnd.saturating_add(self.mss).min(MAX_WINDOW);
            return false;
        }
        self.duplicate_acks = self.duplicate_acks.saturating_add(1);
        if self.duplicate_acks != 3 || self.recover.is_some() {
            return false;
        }
        if self.ecn_end.is_none() {
            self.reduce_threshold(flight);
        }
        self.cwnd = self
            .ssthresh
            .saturating_add(self.mss.saturating_mul(3))
            .min(MAX_WINDOW);
        self.recover = Some(highest_sent);
        self.fast_recovery = true;
        self.acknowledged = 0;
        true
    }

    // A separate ECN epoch must not suppress fast retransmission of real losses.
    // Loss recovery and ECN share the threshold reduction, not retransmit state.
    pub(crate) fn on_ecn(&mut self, ack: Seq, flight: u32, highest_sent: Seq) -> bool {
        if self
            .ecn_end
            .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
            || self
                .recover
                .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
        {
            return false;
        }
        self.reduce_threshold(flight);
        self.cwnd = (self.cwnd / 2).max(self.mss).min(self.ssthresh);
        self.acknowledged = 0;
        self.ecn_end = Some(highest_sent);
        true
    }

    fn reduce_threshold(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(self.mss.saturating_mul(2)).min(MAX_WINDOW);
    }

    // Called only after successful output, not when retransmission is scheduled.
    // All retransmissions start at SND.UNA; retain the furthest end if MSS shrinks.
    pub(crate) fn on_retransmit(&mut self, end: Seq) {
        if self
            .retransmitted_end
            .is_none_or(|old| end.serial_cmp(old) == Some(Ordering::Greater))
        {
            self.retransmitted_end = Some(end);
        }
    }

    pub(crate) fn on_timeout(&mut self, flight: u32, highest_sent: Seq) {
        // Repeated RTOs for the same unacknowledged segment retain ssthresh.
        // RFC 3168 section 6.1.2: loss of a retransmission is new congestion,
        // even inside the ECN epoch. An original-flight loss shares its reduction.
        if !self.timeout_retransmitted
            && (self.ecn_end.is_none() || self.retransmitted_end.is_some())
        {
            self.reduce_threshold(flight);
        }
        self.ecn_end = None;
        self.timeout_retransmitted = true;
        self.recover = Some(highest_sent);
        self.fast_recovery = false;
        self.cwnd = self.mss;
        self.acknowledged = 0;
        self.reset_duplicate_acks();
    }

    pub(crate) fn reset_duplicate_acks(&mut self) {
        self.duplicate_acks = 0;
    }

    pub(crate) fn restart_after_idle(&mut self) {
        self.cwnd = self.cwnd.min(Self::initial_window(self.mss));
        self.acknowledged = 0;
        self.reset_duplicate_acks();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Partial test: estimator vectors and capped backoff; does not test Karn sample
    // exclusion or timer lifecycle.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
    //= type=test
    //# The RTO MUST be computed according to the algorithm in [10], including Karn's
    //# algorithm for taking RTT samples (MUST-18).
    fn rtt_vectors_and_backoff() {
        let mut rtt = RttEstimator::new();
        assert_eq!(rtt.rto(), 1_000_000);
        rtt.sample(1_000_000);
        assert_eq!(
            (rtt.srtt, rtt.variance, rtt.rto()),
            (Some(1_000_000), 500_000, 3_000_000)
        );
        rtt.sample(2_000_000);
        assert_eq!(
            (rtt.srtt, rtt.variance, rtt.rto()),
            (Some(1_125_000), 625_000, 3_625_000)
        );
        rtt.sample(1_000_000);
        assert_eq!(
            (rtt.srtt, rtt.variance, rtt.rto()),
            (Some(1_109_375), 500_000, 3_109_375)
        );
        rtt.backoff();
        // Partial test: doubling the RTO; slow start and congestion avoidance are tested
        // separately.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
        //= type=test
        //# A TCP endpoint MUST implement the basic congestion control algorithms slow
        //# start, congestion avoidance, and exponential backoff of RTO to avoid creating
        //# congestion collapse conditions (MUST-19).
        assert_eq!(rtt.rto(), 6_218_750);
        for _ in 0..100 {
            rtt.backoff();
        }
        assert_eq!(rtt.rto(), MAX_RTO);
        rtt.sample(1_000_000);
        assert!(rtt.rto() < MAX_RTO);
    }

    #[test]
    fn rtt_floor_granularity_and_extremes() {
        let mut rtt = RttEstimator::new();
        rtt.sample(0);
        assert_eq!(rtt.rto(), MIN_RTO);
        rtt.sample(1);
        assert_eq!(rtt.rto(), MIN_RTO);
        let mut rtt = RttEstimator::new();
        for _ in 0..100 {
            rtt.sample(2_000_000);
        }
        assert_eq!(rtt.rto(), 2_001_000);
        let mut rtt = RttEstimator::new();
        rtt.sample(u64::MAX);
        rtt.sample(u64::MAX);
        assert_eq!(rtt.srtt, Some(u64::MAX));
        assert_eq!(rtt.rto(), MAX_RTO);
        rtt.sample(0);
        assert_eq!(rtt.srtt, Some((7 * u64::MAX as u128 / 8) as u64));
        assert_eq!(rtt.rto(), MAX_RTO);
    }

    #[test]
    // Partial test: initial window, ACK-driven growth, timeout reduction, and congestion-
    // avoidance byte counting; not end-to-end congestion-control conformance.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //= type=test
    //# A TCP endpoint MUST implement the basic congestion control algorithms slow start,
    //# congestion avoidance, and exponential backoff of RTO to avoid creating congestion
    //# collapse conditions (MUST-19).
    fn initial_slow_start_and_byte_counting() {
        for (mss, window) in [(500, 2_000), (1_000, 4_000), (1_460, 4_380), (3_000, 6_000)] {
            assert_eq!(Congestion::new(mss).cwnd(), window);
        }
        let mut c = Congestion::new(1_000);
        c.on_ack(Seq(100), 100, 0);
        assert_eq!(c.cwnd(), 4_100);
        c.on_ack(Seq(2_100), 2_000, 0);
        assert_eq!(c.cwnd(), 5_100);
        c.on_timeout(8_000, Seq(10_000));
        assert_eq!(c.ssthresh(), 4_000);
        for i in 1..=3 {
            c.on_ack(Seq(i * 1_000), 1_000, 5_000);
        }
        assert_eq!(c.cwnd(), 4_000);
        for i in 1..4_000 {
            c.on_ack(Seq(3_000 + i), 1, 5_000);
        }
        assert_eq!(c.cwnd(), 4_000);
        c.on_ack(Seq(7_000), 1, 5_000);
        assert_eq!(c.cwnd(), 5_000);
        c.on_ack(Seq(7_000), 0, 5_000);
        assert_eq!(c.cwnd(), 5_000);
    }

    fn three_duplicates(c: &mut Congestion, flight: u32, end: Seq) -> bool {
        assert!(!c.on_duplicate_ack(flight, end));
        assert!(!c.on_duplicate_ack(flight, end));
        c.on_duplicate_ack(flight, end)
    }

    #[test]
    fn newreno_partial_and_full_ack() {
        let mut c = Congestion::new(1_000);
        assert!(three_duplicates(&mut c, 8_000, Seq(8_000)));
        assert_eq!((c.ssthresh(), c.cwnd()), (4_000, 7_000));
        assert!(!c.on_duplicate_ack(8_000, Seq(8_000)));
        assert_eq!(c.cwnd(), 8_000);
        assert!(c.on_ack(Seq(2_000), 2_000, 6_000));
        assert_eq!(c.cwnd(), 7_000);
        assert!(c.on_ack(Seq(2_500), 500, 5_500));
        assert_eq!(c.cwnd(), 6_500);
        assert!(!c.on_duplicate_ack(5_500, Seq(8_000)));
        assert_eq!(c.cwnd(), 7_500);
        assert!(!c.on_ack(Seq(8_000), 5_500, 0));
        assert_eq!(c.cwnd(), 2_000);
        assert!(!c.fast_recovery);
        assert!(!three_duplicates(&mut c, 4_000, Seq(12_000)));
        c.on_ack(Seq(8_001), 1, 3_999);
        assert!(three_duplicates(&mut c, 3_999, Seq(12_000)));
    }

    #[test]
    fn timeout_marker_boundaries_and_wrap() {
        for end in [Seq(10_000), Seq(0), Seq(u32::MAX)] {
            let mut c = Congestion::new(1_000);
            c.on_timeout(10_000, end);
            assert_eq!((c.cwnd(), c.ssthresh()), (1_000, 5_000));
            c.on_timeout(2_000, end);
            assert_eq!(c.ssthresh(), 5_000);
            assert!(!three_duplicates(&mut c, 10_000, end));
            c.on_ack(end.wrapping_add(u32::MAX), 1, 1);
            assert!(!three_duplicates(&mut c, 4_000, end.wrapping_add(4_000)));
            c.on_ack(end, 1, 4_000);
            assert!(!three_duplicates(&mut c, 4_000, end.wrapping_add(4_000)));
            c.on_ack(end.wrapping_add(1), 1, 3_999);
            assert!(three_duplicates(&mut c, 3_999, end.wrapping_add(4_000)));
            assert!(c.on_ack(end.wrapping_add(1_001), 1_000, 2_999));
            assert!(!c.on_ack(end.wrapping_add(4_000), 2_999, 0));
            c.on_timeout(8_000, end.wrapping_add(8_000));
            assert_eq!(c.ssthresh(), 4_000);
        }
    }

    #[test]
    fn mss_idle_reset_and_saturation() {
        let mut c = Congestion::new(1_000);
        c.on_ack(Seq(1_000), 1_000, 0);
        c.set_mss(500);
        assert_eq!(c.cwnd(), 2_500);
        c.restart_after_idle();
        assert_eq!(c.cwnd(), 2_000);
        c.on_timeout(10_000, Seq(10_000));
        c.restart_after_idle();
        assert_eq!(c.cwnd(), 500);
        c.set_mss(1_000);
        assert_eq!(c.cwnd(), 1_000);
        let mut c = Congestion::new(u32::MAX);
        assert_eq!(c.cwnd(), MAX_WINDOW);
        c.on_ack(Seq(1), u32::MAX, u32::MAX);
        assert_eq!(c.cwnd(), MAX_WINDOW);
        assert!(three_duplicates(&mut c, u32::MAX, Seq(10)));
        c.on_duplicate_ack(u32::MAX, Seq(10));
        assert_eq!((c.cwnd(), c.ssthresh()), (MAX_WINDOW, MAX_WINDOW));
        c.set_mss(u32::MAX);
        c.on_timeout(u32::MAX, Seq(10));
        assert_eq!((c.cwnd(), c.ssthresh()), (MAX_WINDOW, MAX_WINDOW));
        let mut c = Congestion::new(1_000);
        c.on_duplicate_ack(4_000, Seq(4_000));
        c.on_duplicate_ack(4_000, Seq(4_000));
        c.reset_duplicate_acks();
        assert!(three_duplicates(&mut c, 4_000, Seq(4_000)));
    }

    #[test]
    #[should_panic]
    fn zero_mss_rejected() {
        Congestion::new(0);
    }

    #[test]
    #[should_panic]
    fn zero_mss_update_rejected() {
        Congestion::new(1_000).set_mss(0);
    }
    #[test]
    fn ecn_retransmission_loss_and_ack_boundaries_wrap() {
        for base in [Seq(100), Seq(u32::MAX - 12_499)] {
            for acked_retransmission in [0, 500, 1000] {
                let end = base.wrapping_add(16_000);
                let mut c = Congestion::new(1000);
                assert!(c.on_ecn(base, 16_000, end));
                assert_eq!(c.ssthresh(), 8000);
                assert!(three_duplicates(&mut c, 16_000, end));
                c.on_retransmit(base.wrapping_add(1000));
                assert!(c.on_ack(base.wrapping_add(12_000), 12_000, 4000));
                c.on_retransmit(base.wrapping_add(13_000));
                // A shorter retransmission must not forget still-outstanding bytes.
                c.on_retransmit(base.wrapping_add(12_500));
                if acked_retransmission != 0 {
                    assert!(c.on_ack(
                        base.wrapping_add(12_000 + acked_retransmission),
                        acked_retransmission,
                        4000 - acked_retransmission
                    ));
                }
                c.on_timeout(4000 - acked_retransmission, end);
                let threshold = if acked_retransmission == 1000 {
                    8000
                } else {
                    2000
                };
                assert_eq!(c.ssthresh(), threshold);
                c.on_timeout(4000 - acked_retransmission, end);
                assert_eq!(c.ssthresh(), threshold);
            }
        }
    }

    #[test]
    fn ecn_loss_recovery_shares_reduction_but_not_retransmission() {
        for base in [Seq(0), Seq(u32::MAX - 3_999)] {
            let end = base.wrapping_add(4_000);
            let mut c = Congestion::new(1_000);
            assert!(c.on_ecn(base, 4_000, end));
            assert_eq!((c.cwnd(), c.ssthresh()), (2_000, 2_000));
            assert!(!c.on_ecn(end, 4_000, end));
            // A real loss in the ECN window still fast retransmits, without
            // a second threshold reduction (flight is intentionally smaller).
            assert!(three_duplicates(&mut c, 2_000, end));
            assert_eq!(c.ssthresh(), 2_000);
            assert!(!c.on_ecn(base, 2_000, end));
            assert!(c.on_ack_with_ecn(base.wrapping_add(1_000), 1_000, 1_000, true));
            assert!(!c.on_ack_with_ecn(end, 1_000, 0, true));
            assert!(!c.fast_recovery);
            assert!(!c.on_ecn(end, 2_000, end));
            assert!(c.on_ecn(end.wrapping_add(1), 2_000, end.wrapping_add(2_000)));

            let mut c = Congestion::new(1_000);
            assert!(three_duplicates(&mut c, 8_000, end));
            let threshold = c.ssthresh();
            assert!(!c.on_ecn(end, 8_000, end));
            assert_eq!(c.ssthresh(), threshold);
            c.on_timeout(2_000, end);
            assert_eq!(c.cwnd(), 1_000);
            assert!(!c.on_ecn(end, 2_000, end));

            let mut c = Congestion::new(1_000);
            assert!(c.on_ecn(base, 8_000, end));
            let threshold = c.ssthresh();
            c.on_timeout(2_000, end);
            assert_eq!(c.ssthresh(), threshold);
            assert_eq!(c.cwnd(), 1_000);
        }
    }
}
