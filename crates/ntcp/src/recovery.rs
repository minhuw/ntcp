use core::cmp::Ordering;

use crate::{connection::CallerTimebase, cubic::Cubic, seq::Seq};

const MIN_RTO: u64 = 1_000_000;
const MAX_RTO: u64 = 60_000_000;
const MAX_WINDOW: u32 = 0x7fff_ffff;

#[derive(Clone, Debug)]
pub(crate) struct RttEstimator {
    srtt: Option<u64>,
    variance: u64,
    rto: u64,
    minimum: u64,
    timebase: CallerTimebase,
    #[cfg(test)]
    pub(crate) updates: usize,
}

// Partial evidence: estimator arithmetic and bounded backoff only. The connection selects
// unambiguous samples (Karn), manages timers, and retransmits; this helper alone does not
// establish RFC 6298 conformance.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
//# The RTO MUST be computed according to the algorithm in [10], including Karn's algorithm
//# for taking RTT samples (MUST-18).
impl RttEstimator {
    // Initial estimator RTO is MIN_RTO regardless of configured sampled minimum.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=Initial estimator RTO is MIN_RTO regardless of configured sampled minimum.
    //# (2.1) Until a round-trip time (RTT) measurement has been made for a segment sent
    //# between the sender and receiver, the sender SHOULD set RTO <- 1 second, though the
    //# "backing off" on repeated retransmission discussed in (5.5) still applies.
    #[cfg(test)]
    pub(crate) fn new(minimum: u64) -> Self {
        Self::with_timebase(minimum, CallerTimebase::default())
    }

    pub(crate) fn with_timebase(minimum: u64, timebase: CallerTimebase) -> Self {
        assert!((1..=MAX_RTO).contains(&minimum));
        Self {
            minimum: timebase.ticks_from_us(minimum),
            timebase,
            #[cfg(test)]
            updates: 0,
            srtt: None,
            variance: 0,
            rto: timebase.ticks_from_us(MIN_RTO),
        }
    }

    pub(crate) fn srtt(&self) -> Option<u64> {
        self.srtt
    }

    pub(crate) fn variance(&self) -> u64 {
        self.variance
    }

    pub(crate) fn rto(&self) -> u64 {
        self.rto
    }

    // The caller excludes ambiguous retransmission samples (Karn's algorithm).
    // G=1000us is conservative RTO policy padding, not a declaration or measurement
    // of the physical clock resolution. Samples/averages retain caller ticks.
    // Estimator evidence for default/configured >=1s floors; G=1000us, K=4, alpha=1/8, beta=1/4. Explicit subsecond Linux compatibility is a scoped SHOULD departure, not universal MUST conformance; connection sampling/timer evidence is separate.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-1
    //= reason=Estimator evidence for default/configured >=1s floors; G=1000us, K=4, alpha=1/8, beta=1/4. Explicit subsecond Linux compatibility is a scoped SHOULD departure, not universal MUST conformance; connection sampling/timer evidence is separate.
    //# However, a TCP MUST NOT be more aggressive than the following algorithms allow.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# (2.2) When the first RTT measurement R is made, the host MUST set
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# (2.3) When a subsequent RTT measurement R' is made, a host MUST set
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# That is, updating RTTVAR and SRTT MUST be computed in the above order.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# The above SHOULD be computed using alpha=1/8 and beta=1/4 (as suggested in [JK88]).
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# After the computation, a host MUST update RTO <- SRTT + max (G, K*RTTVAR)
    // Estimator evidence for default/configured >=1s floors; G=1000us, K=4, alpha=1/8, beta=1/4. Explicit subsecond Linux compatibility is a scoped SHOULD departure, not universal MUST conformance; connection sampling/timer evidence is separate.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=Estimator evidence for default/configured >=1s floors; G=1000us, K=4, alpha=1/8, beta=1/4. Explicit subsecond Linux compatibility is a scoped SHOULD departure, not universal MUST conformance; connection sampling/timer evidence is separate.
    //# (2.4) Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be
    //# rounded up to 1 second.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# (2.5) A maximum value MAY be placed on RTO provided it is at least 60 seconds.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-4
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# However, if the K*RTTVAR term in the RTO calculation equals zero, the variance term
    //# MUST be rounded to G seconds (i.e., use the equation given in step 2.3).
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# To compute the current RTO, a TCP sender maintains two state variables, SRTT (smoothed
    //# round-trip time) and RTTVAR (round-trip time variation). In addition, we assume a
    //# clock granularity of G seconds.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# SRTT <- R RTTVAR <- R/2 RTO <- SRTT + max (G, K*RTTVAR) where K = 4.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'| SRTT <- (1 - alpha) * SRTT + alpha
    //# * R'
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# The value of SRTT used in the update to RTTVAR is its value before updating SRTT
    //# itself using the second assignment.
    // RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=RTT estimator only; integer caller ticks with G=1000us, K=4, alpha=1/8, beta=1/4; caller sampling and timer lifecycle audited separately.
    //# Note that after retransmitting, once a new RTT measurement is obtained (which can only
    //# happen when new data has been sent and acknowledged), the computations outlined in
    //# Section 2 are performed, including the computation of RTO, which may result in
    //# "collapsing" RTO back down after it has been subject to exponential back off (rule
    //# 5.5).
    pub(crate) fn sample(&mut self, rtt_ticks: u64) {
        #[cfg(test)]
        {
            self.updates += 1;
        }
        let srtt = match self.srtt {
            None => {
                self.variance = rtt_ticks / 2;
                rtt_ticks
            }
            Some(old) => {
                // Widen before averaging: even u64::MAX samples remain accurate.
                self.variance =
                    ((3 * self.variance as u128 + old.abs_diff(rtt_ticks) as u128) / 4) as u64;
                ((7 * old as u128 + rtt_ticks as u128) / 8) as u64
            }
        };
        self.srtt = Some(srtt);
        self.rto = srtt
            .saturating_add(
                self.variance
                    .saturating_mul(4)
                    .max(self.timebase.ticks_from_us(1_000)),
            )
            .clamp(self.minimum, self.timebase.ticks_from_us(MAX_RTO));
    }

    // Partial evidence: exponential RTO backoff only; congestion-window algorithms are in
    // Congestion and timer orchestration is in the connection.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //# A TCP endpoint MUST implement the basic congestion control algorithms slow start,
    //# congestion avoidance, and exponential backoff of RTO to avoid creating congestion
    //# collapse conditions (MUST-19).
    // Estimator exponential doubling capped at 60 seconds; timeout caller invokes this before successful output commits the timer.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=Estimator exponential doubling capped at 60 seconds; timeout caller invokes this before successful output commits the timer.
    //# (2.1) Until a round-trip time (RTT) measurement has been made for a segment sent
    //# between the sender and receiver, the sender SHOULD set RTO <- 1 second, though the
    //# "backing off" on repeated retransmission discussed in (5.5) still applies.
    // Estimator exponential doubling capped at 60 seconds; timeout caller invokes this before successful output commits the timer.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= reason=Estimator exponential doubling capped at 60 seconds; timeout caller invokes this before successful output commits the timer.
    //# (2.5) A maximum value MAY be placed on RTO provided it is at least 60 seconds.
    // Estimator exponential doubling capped at 60 seconds; timeout caller invokes this before successful output commits the timer.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= reason=Estimator exponential doubling capped at 60 seconds; timeout caller invokes this before successful output commits the timer.
    //# (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").
    pub(crate) fn backoff(&mut self) {
        self.rto = self
            .rto
            .saturating_mul(2)
            .min(self.timebase.ticks_from_us(MAX_RTO));
    }
}

// Fast recovery behavior; both choices share slow start and congestion avoidance.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
//= reason=Selectable RFC 5681 Reno-style and RFC 6582 NewReno recovery with shared conservative congestion and ECN guards; not a whole external-RFC compliance claim.
//# An endpoint MAY implement such alternative
//# algorithms provided that the algorithms are conformant with the TCP
//# specifications from the IETF Standards Track as described in RFC
//# 2914, RFC 5033 [7], and RFC 8961 [15] (MAY-18).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum RecoveryAlgorithm {
    // RFC 5681 recovery, retaining conservative recovery/ECN epoch guards.
    Reno,
    // RFC 6582 partial-ACK recovery (the default).
    #[default]
    NewReno,
}

// Congestion growth/backoff selection is independent of fast recovery.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    // Existing RFC 5681-compatible byte-counted growth and half-flight backoff.
    #[default]
    Reno,
    // RFC 9438 CUBIC, C=0.4, beta=0.7, with fast convergence.
    Cubic,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum InitialWindow {
    #[default]
    Rfc5681,
    // Experimental RFC 6928 initial/restart window; loss windows stay one MSS.
    Iw10,
}

impl InitialWindow {
    //= https://www.rfc-editor.org/rfc/rfc6928#section-12
    //= reason=No monitoring-backed default deployment is claimed: InitialWindow default and ConnectionConfig default select Rfc5681, and test explicitly asserts this. Iw10 is only explicit opt-in; deployment monitoring remains owed by the enabling actor outside this implementation audit; bounded cache/fallback is implemented.
    //# An increased initial window MUST NOT be turned on by default on systems without such
    //# monitoring capabilities.
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=IW10 is optional and InitialWindow::default is Rfc5681; config default assertion confirms opt-in. This permission does not discharge IW10 fallback/monitoring obligations. Default RFC5681 arithmetic is covered by default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss.
    //# This increase is optional: a TCP MAY start with an initial window that is smaller than
    //# 10 segments.
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=Explicit InitialWindow::Iw10 computes min(10*MSS,max(2*MSS,14600)) with conservative integer cap. Tests assert representative small/normal/jumbo/overflow vectors, negotiated MSS/path/options and initial handshake value. Default RFC5681 arithmetic is covered separately by default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss.
    //# min (10*MSS, max (2*MSS, 14600)) (1)
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //# IW, the initial value of cwnd, MUST be set using the following guidelines as an upper bound.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //# If SMSS > 2190 bytes: IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
    //# If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes): IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
    //# if SMSS <= 1095 bytes: IW = 4 * SMSS bytes and MUST NOT be more than 4 segments
    pub(crate) fn bytes(self, mss: u32) -> u32 {
        match self {
            Self::Rfc5681 => {
                let segments = if mss > 2_190 {
                    2
                } else if mss > 1_095 {
                    3
                } else {
                    4
                };
                mss.saturating_mul(segments)
            }
            Self::Iw10 => mss
                .saturating_mul(10)
                .min(mss.saturating_mul(2).max(14_600)),
        }
        .min(MAX_WINDOW)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Congestion {
    algorithm: RecoveryAlgorithm,
    cubic: Option<Cubic>,
    initial_window: InitialWindow,
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    acknowledged: u64,
    duplicate_acks: u8,
    // Exclusive SND.NXT, not the inclusive highest byte used in RFC 6582.
    recover: Option<Seq>,
    initial_recover: Option<Seq>,
    congestion_avoidance: bool,
    fast_recovery: bool,
    sack_recovery: bool,
    ecn_end: Option<Seq>,
    // TLP repair reduces congestion without starting recovery. This epoch
    // shares that reduction with later original losses, never bars recovery.
    tlp_reduction_end: Option<Seq>,
    timeout_retransmitted: bool,
    // Exclusive end of successfully emitted, still-unacknowledged retransmissions.
    retransmitted_end: Option<Seq>,
}

impl Congestion {
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Initial ssthresh is the maximum serial-safe window; real initial-guard and first-loss traces assert it and its reduction.
    //# The initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size of the largest
    //# possible advertised window), but ssthresh MUST be reduced in response to congestion.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Inclusive initial ISS is stored separately as exclusive ISS+1; NewReno alone requires ACK greater than this boundary. Controller ISS/ISS+1/ISS+2 and wrapping vectors complement real first-flight suppression, subsequent-byte entry and timeout guards; Reno/SACK first-flight behavior is retained.
    //# When the TCP protocol control block is initialized, recover is set to the initial send sequence
    //# number.
    pub(crate) fn new(
        mss: u32,
        algorithm: RecoveryAlgorithm,
        initial_window: InitialWindow,
        iss: Seq,
    ) -> Self {
        assert!(mss > 0);
        let mss = mss.min(MAX_WINDOW);
        Self {
            algorithm,
            cubic: None,
            initial_window,
            mss,
            cwnd: initial_window.bytes(mss),
            ssthresh: MAX_WINDOW,
            acknowledged: 0,
            duplicate_acks: 0,
            recover: None,
            // RFC6582 inclusive ISS is represented by exclusive ISS+1.
            // Unlike a loss epoch, this guard applies only to NewReno.
            initial_recover: Some(iss.wrapping_add(1)),
            congestion_avoidance: false,
            fast_recovery: false,
            sack_recovery: false,
            ecn_end: None,
            tlp_reduction_end: None,
            timeout_retransmitted: false,
            retransmitted_end: None,
        }
    }

    pub(crate) fn with_congestion(
        mut self,
        algorithm: CongestionAlgorithm,
        timebase: CallerTimebase,
    ) -> Self {
        self.cubic = match algorithm {
            CongestionAlgorithm::Reno => None,
            CongestionAlgorithm::Cubic => Some(Cubic::new(timebase)),
        };
        self
    }

    // Caller invokes only after committed data output and SND.NXT accounting.
    pub(crate) fn on_data_sent(&mut self, now: u64, flight: u32, end: Seq, cwnd_limited: bool) {
        let recovery = self.in_recovery();
        if let Some(cubic) = &mut self.cubic {
            cubic.sent(now, flight, self.cwnd, end, recovery, cwnd_limited);
        }
    }

    // Validated cumulative ACK, with the freshly updated smoothed RTT in
    // caller ticks. Reno deliberately does not consume the timing context.
    pub(crate) fn prepare_ack(
        &mut self,
        now: u64,
        rtt: Option<u64>,
        ack: Seq,
        acked: u32,
        send_window: u32,
    ) {
        if let Some(cubic) = &mut self.cubic {
            cubic.prepare_ack(now, rtt, ack, acked, send_window >= self.cwnd);
        }
    }

    pub(crate) fn on_window_update(&mut self, now: u64, window: u32) {
        if window < self.cwnd
            && let Some(cubic) = &mut self.cubic
        {
            cubic.receiver_limited(now);
        }
    }

    pub(crate) fn initial_window(&self) -> u32 {
        self.initial_window.bytes(self.mss)
    }

    // SYN negotiation selects the byte bound anew; path changes preserve segment counts.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Default RFC5681 SYN timeout selects one effective MSS; opt-in IW10 reduction is triggered by more than one committed retry, not merely the first timeout.
    //# Further, if the SYN or SYN/ACK is lost, the initial window used by a sender after a
    //# correctly transmitted SYN MUST be one segment consisting of at most SMSS bytes.
    pub(crate) fn set_initial_mss(&mut self, mss: u32, syn_timed_out: bool) {
        self.set_mss(mss);
        self.cwnd = if syn_timed_out {
            self.mss
        } else {
            self.initial_window()
        };
    }

    pub(crate) fn prr_window(&mut self, window: u32) {
        self.cwnd = window.min(MAX_WINDOW);
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.4
    //# On the completion of a PRR episode, PRR executes the following:
    //#
    //#    cwnd = ssthresh
    pub(crate) fn complete_prr(&mut self) {
        self.cwnd = self.ssthresh;
        self.congestion_avoidance = true;
        self.acknowledged = 0;
    }

    pub(crate) fn cwnd(&self) -> u32 {
        self.cwnd
    }

    pub(crate) fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=set_mss scales cwnd by new/old MSS on a decrease; negotiated/path/timestamp vectors assert exact byte ratio. No claim that discovery itself is supplied by TCP.
    //# When initial congestion windows of more than one segment are implemented along with Path
    //# MTU Discovery [RFC1191], and the MSS being used is found to be too large, the congestion
    //# window cwnd SHOULD be reduced to prevent large bursts of smaller segments.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=set_mss scales cwnd by new/old MSS on a decrease; negotiated/path/timestamp vectors assert exact byte ratio. No claim that discovery itself is supplied by TCP.
    //# Specifically, cwnd SHOULD be reduced by the ratio of the old segment size to the new
    //# segment size.
    pub(crate) fn set_mss(&mut self, mss: u32) {
        assert!(mss > 0);
        let mss = mss.min(MAX_WINDOW);
        if mss < self.mss {
            // RFC 5681: preserve the segment count when the path MSS falls.
            self.cwnd = ((self.cwnd as u64 * mss as u64) / self.mss as u64) as u32;
        }
        if mss != self.mss
            && let Some(cubic) = &mut self.cubic
        {
            if mss < self.mss && self.ssthresh != MAX_WINDOW {
                self.ssthresh =
                    (u64::from(self.ssthresh) * u64::from(mss) / u64::from(self.mss)) as u32;
            }
            cubic.mss_changed(self.mss, mss);
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
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-1
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# This document applies to TCP connections that are unable to use the TCP Selective
    //# Acknowledgment (SACK) option, either because the option is not locally supported or
    //# because the TCP peer did not indicate a willingness to use SACK.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# When in fast recovery, this variable records the send sequence number that must be
    //# acknowledged before the fast recovery procedure is declared to be over.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
    //= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
    //# The NewReno modification applies to the fast recovery procedure that begins when three
    //# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
    //# ACK arrives that acknowledges all of the data up to and including the data that was
    //# outstanding when the fast recovery procedure began.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# The procedures specified in Section 3.2 of [RFC5681] are followed, with the
    //# modifications listed below.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# When the third duplicate ACK is received, the TCP sender first checks the value of
    //# recover to see if the Cumulative Acknowledgment field covers more than recover. If so,
    //# the value of recover is incremented to the value of the highest sequence number
    //# transmitted by the TCP so far. The TCP then enters fast retransmit (step 2 of Section
    //# 3.2 of [RFC5681]). If not, the TCP does not enter fast retransmit and does not reset
    //# ssthresh.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# If this ACK acknowledges all of the data up to and including recover, then the ACK
    //# acknowledges all the intermediate segments sent between the original transmission of
    //# the lost segment and the receipt of the third duplicate ACK. Set cwnd to either (1)
    //# min (ssthresh, max(FlightSize, SMSS) + SMSS) or (2) ssthresh, where ssthresh is the
    //# value set when fast retransmit was entered, and where FlightSize in (1) is the amount
    //# of data presently outstanding.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# Exit the fast recovery procedure.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# If this ACK does *not* acknowledge all of the data up to and including recover, then
    //# this is a partial ACK.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=NewReno partial ACK schedules retx_pending; committed output starts at snd_una. newreno_partial_ack_wire_timer_and_exit_boundaries asserts each missing sequence/payload, continued recovery and failed-output rollback, including wrap.
    //# In this case, retransmit the first unacknowledged segment.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# Deflate the congestion window by the amount of new data acknowledged by the Cumulative
    //# Acknowledgment field. If the partial ACK acknowledges at least one SMSS of new data,
    //# then add back SMSS bytes to the congestion window.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=newreno_partial_ack_wire_timer_and_exit_boundaries asserts no fresh output with flight>=cwnd, one fresh MSS with credit, rwnd/SWS suppression then permission, MSS payload bounds and failed-output rollback.
    //# Send a new segment if permitted by the new value of cwnd.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# Do not exit the fast recovery procedure (i.e., if any duplicate ACKs subsequently
    //# arrive, execute step 4 of Section 3.2 of [RFC5681]).
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# Because the acknowledgment field contains the sequence number that the sender next
    //# expects to receive, the acknowledgment "ack_number" covers more than recover when
    //# ack_number - 1 > recover; i.e., at least one byte more of data is acknowledged beyond
    //# the highest byte that was outstanding when fast retransmit was last entered.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Selected full-ACK option1 cwnd=min(ssthresh,max(FlightSize,SMSS)+SMSS). Lost-duplicate-ACK wire trace newreno_partial_ack_wire_timer_and_exit_boundaries polls to exhaustion: two fresh MSS at zero flight, one at residual one-MSS flight.
    //# In Section 3.2, step 3 above, it is noted that implementations should take measures to
    //# avoid a possible burst of data when leaving fast recovery, in case the amount of new
    //# data that the sender is eligible to send due to the new value of the congestion window
    //# is large.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# An implementation may want to use a separate flag to record whether or not it is
    //# presently in the fast recovery procedure.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# The use of the value of the duplicate acknowledgment counter for this purpose is not
    //# reliable, because it can be reset upon window updates and out-of- order
    //# acknowledgments.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# Entry into fast recovery is only possible when the Cumulative Acknowledgment field
    //# covers more than the state variable recover.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# When updating the Cumulative Acknowledgment field outside of fast recovery, the state
    //# variable recover may also need to be updated in order to continue to permit possible
    //# entry into fast recovery (Section 3.2, step 2). This issue arises when an update of
    //# the Cumulative Acknowledgment field results in a sequence wraparound that affects the
    //# ordering between the Cumulative Acknowledgment field and the state variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. recover is an exclusive end; equal ACK fully covers the prior flight, greater ACK clears the reentry guard. Separate fast_recovery flag survives duplicate-counter resets.
    //# Note that after cwnd is set based on the procedure for exiting fast recovery (Section
    //# 3.2, step 3), cwnd should not be updated until a further event occurs (e.g., arrival
    //# of an ack, or timeout) after this adjustment.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# * MAY increment cwnd by SMSS bytes
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# The RECOMMENDED way to increase cwnd during congestion avoidance is to count the number
    //# of bytes that have been acknowledged by ACKs for new data.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=RecoveryAlgorithm::Reno only, without negotiated SACK: on first advancing ACK sets cwnd=ssthresh; reno_and_newreno_recovery_exit explicitly asserts 4000 for partial and full Reno ACKs. NewReno/SACK/RACK/PRR use enhanced section4.3 recovery, not immediate Reno deflation.
    //# When the next ACK arrives that acknowledges previously unacknowledged data, a TCP MUST
    //# set cwnd to ssthresh (the value set in step 2).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# The slow start algorithm is used when cwnd < ssthresh, while the congestion avoidance
    //# algorithm is used when cwnd > ssthresh. When cwnd and ssthresh are equal, the sender may
    //# use either slow start or congestion avoidance.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# During slow start, a TCP increments cwnd by at most SMSS bytes for each ACK received
    //# that cumulatively acknowledges new data. Slow start ends when cwnd exceeds ssthresh (or,
    //# optionally, when it reaches it, as noted above) or when congestion is observed. While
    //# traditionally TCP implementations have increased cwnd by precisely SMSS bytes upon
    //# receipt of an ACK covering new data, we RECOMMEND that TCP implementations increase
    //# cwnd, per:
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# cwnd += min (N, SMSS) (2)
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# We note that [RFC3465] allows for cwnd increases of more than SMSS bytes for incoming
    //# acknowledgments during slow start on an experimental basis; however, such behavior is
    //# not allowed as part of the standard.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= reason=Recommendation to employ multi-loss recovery: default NewReno handles partial ACKs; opt-in negotiated SACK repairs multiple holes. These tests evidence algorithm selection and multi-loss repair only, not every section4.3 general bound (TODOs remain).
    //# We RECOMMEND that TCP implementors employ some form of advanced loss recovery that can
    //# cope with multiple losses in a window of data. The algorithms detailed in [RFC3782] and
    //# [RFC3517] conform to the general principles outlined above. We note that while these are
    //# not the only two algorithms that conform to the above general principles these two
    //# algorithms have been vetted by the community and are currently on the Standards Track.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-5
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# In response to the ACK division attack outlined in [SCWA99], this document RECOMMENDS
    //# increasing the congestion window based on the number of bytes newly acknowledged in each
    //# arriving ACK rather than by a particular constant on each arriving ACK (as outlined in
    //# section 3.1).
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=Connection-boundary otherwise-identical ACK traces contrast ordinary MSS growth with advancing ECE suppression and non-ECE duplicate recovery inflation, for Reno/NewReno and ECN on/off.
    //# TCP also follows the normal procedures for increasing the congestion window when it receives ACK packets without the ECN-Echo bit set [RFC2581].
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=Positive-window Reno/NewReno ECE recovery exits cap at pre-ACK cwnd. Narrow zero-cwnd/zero-flight NewReno SHOULD departure restores RFC6582 option1 with RTO-length ECN pause; newreno_partial_zero_full_ece_restarts_after_ecn_pause proves liveness without waiving ordinary no-growth. ecn_duplicate_entry_below_threshold_and_covering_ack_exit traces real reductions to cwnd=64<ssthresh=128, duplicate-ECE entry and covering-ECE exit without growth, with non-ECE exit restoring 128; SACK exit already caps at cwnd. Ordinary advancing and duplicate growth contrasts are separately tested.
    //# The sending
    //# TCP SHOULD NOT increase the congestion window in response to the
    //# receipt of an ECN-Echo ACK packet.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
    //# * SHOULD increment cwnd per equation (2) once per RTT
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
    //# * MUST NOT increment cwnd by more than SMSS bytes
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
    //# Note that during congestion avoidance, cwnd MUST NOT be
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= reason=NewReno/SACK/RACK/RACK+PRR actual entries and covering ACK exits give cwnd2000 below ssthresh4000; first next MSS ACK leaves cwnd unchanged, second grows by one MSS; RTO restores slow start. No global PRR/half-flight claim.
    //# has been successfully retransmitted, cwnd MUST be set to no more than ssthresh and congestion
    //# avoidance MUST be used to further increase cwnd.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Actual bounded flight output followed one RTT later by delayed or one-byte divided ACKs: exact cumulative byte ledger and at most one SMSS increase for each of three flights, including wrap.
    //# The RECOMMENDED way to increase cwnd during congestion avoidance is to count the number of
    //# bytes that have been acknowledged by ACKs for new data. (A drawback of this implementation is
    //# that it requires maintaining an additional state variable.) When the number of bytes
    //# acknowledged reaches cwnd, then cwnd can be incremented by up to SMSS bytes. Note that during
    //# congestion avoidance, cwnd MUST NOT be increased by more than SMSS bytes per RTT. This method
    //# both allows TCPs to increase cwnd by one segment per RTT in the face of delayed ACKs and
    //# provides robustness against ACK Division attacks.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= reason=NewReno/SACK/RACK/RACK+PRR actual entries and covering ACK exits give cwnd2000 below ssthresh4000; first next MSS ACK leaves cwnd unchanged, second grows by one MSS; RTO restores slow start. No global PRR/half-flight claim.
    //# Finally, after all loss in the given window of segments has been successfully retransmitted,
    //# cwnd MUST be set to no more than ssthresh and congestion avoidance MUST be used to further
    //# increase cwnd.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Actual ten-segment loss trace with lost duplicate ACKs yields literal32-36+4=0, not an MSS floor. Partial hole repair ignores fresh-data credit; lost repair RTO restores one-MSS progress. Controller signed-expression vectors cover positive remainder and negative saturation. newreno_partial_zero_full_ece_restarts_after_ecn_pause covers zero/full-ECE liveness with an explicitly scoped RFC3168 SHOULD departure.
    //# Deflate the congestion window by the amount of new data acknowledged by the Cumulative
    //# Acknowledgment field. If the partial ACK acknowledges at least one SMSS of new data, then add
    //# back SMSS bytes to the congestion window.
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
        self.observe_ack(ack);
        if acked == 0 {
            return false;
        }
        self.reset_duplicate_acks();
        self.timeout_retransmitted = false;
        if self
            .tlp_reduction_end
            .is_some_and(|end| ack.serial_cmp(end) == Some(Ordering::Greater))
        {
            self.tlp_reduction_end = None;
        }
        let relation = self.recover.and_then(|recover| ack.serial_cmp(recover));
        if relation == Some(Ordering::Greater) {
            // Reno/NewReno retain the epoch at equality; SACK entry checks coverage.
            self.recover = None;
        }
        if self.sack_recovery {
            if matches!(relation, Some(Ordering::Equal | Ordering::Greater)) {
                self.cwnd = self.cwnd.min(self.ssthresh).min(
                    flight_after_ack
                        .max(self.mss)
                        .saturating_add(self.mss)
                        .min(MAX_WINDOW),
                );
                self.sack_recovery = false;
                self.congestion_avoidance = true;
                self.acknowledged = 0;
            }
            return false;
        }
        if self.fast_recovery {
            let exit_cap = if ece { self.cwnd } else { MAX_WINDOW };
            if self.algorithm == RecoveryAlgorithm::Reno && relation.is_some() {
                // Retain recover and the independent ECN epoch: exiting fast recovery
                // must not allow a second reduction for the same flight.
                //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
                //# When the next ACK arrives that acknowledges previously
                //# unacknowledged data, a TCP MUST set cwnd to ssthresh (the value
                //# set in step 2).
                self.cwnd = self.ssthresh.min(exit_cap);
                self.fast_recovery = false;
                self.congestion_avoidance = true;
                self.acknowledged = 0;
                return false;
            }
            if matches!(relation, Some(Ordering::Equal | Ordering::Greater)) {
                // Narrow departure from RFC3168 section6.1.2 no-growth SHOULD:
                // a zero window with no flight has neither ACK clock nor RTO
                // to restart it. Restore RFC6582 option (1) only here. The
                // Connection retains its one-window ECN RTO-length send pause.
                let exit_cap = if self.cwnd == 0 && flight_after_ack == 0 {
                    MAX_WINDOW
                } else {
                    exit_cap
                };
                // RFC 6582 option (1) limits the burst after a full ACK.
                self.cwnd = self.ssthresh.min(exit_cap).min(
                    flight_after_ack
                        .max(self.mss)
                        .saturating_add(self.mss)
                        .min(MAX_WINDOW),
                );
                self.fast_recovery = false;
                self.congestion_avoidance = true;
                self.acknowledged = 0;
                return false;
            }
            if relation == Some(Ordering::Less) {
                // Saturate the complete signed expression, not its subtraction:
                // an ACK may cover almost the entire inflated window.
                self.cwnd = (i64::from(self.cwnd) - i64::from(acked)
                    + if acked >= self.mss {
                        i64::from(self.mss)
                    } else {
                        0
                    })
                .clamp(0, i64::from(MAX_WINDOW)) as u32;
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
        if let Some(cubic) = &mut self.cubic {
            if !cubic.can_grow() {
                return false;
            }
            // Published section 4.10 uses slow start at equality. Recovery's
            // explicit congestion-avoidance state remains authoritative.
            if !self.congestion_avoidance && self.cwnd <= self.ssthresh {
                self.cwnd = self
                    .cwnd
                    .saturating_add(acked.min(self.mss))
                    .min(MAX_WINDOW);
            } else {
                self.cwnd = cubic.grow(self.cwnd, self.mss);
            }
            return false;
        }
        if !self.congestion_avoidance && self.cwnd < self.ssthresh {
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

    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= reason=Loss/ECN/recovery epochs guard the congestion reduction for a repaired tail loss.
    //# If the TLP
    //# sender does not receive such an indication, then it MUST assume that
    //# the original data segment, the TLP retransmission, or a corresponding
    //# ACK was lost for congestion control purposes.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= reason=Reduces cwnd/threshold as a recovery event without retransmitting repaired bytes; shares prior ECN/loss reduction epoch.
    //# The sender then
    //# SHOULD invoke a congestion control response equivalent to a fast
    //# recovery.
    pub(crate) fn on_tlp_repair(&mut self, ack: Seq, flight: u32, highest_sent: Seq) -> bool {
        if self.in_recovery()
            || self
                .recover
                .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
            || self
                .tlp_reduction_end
                .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
        {
            return false;
        }
        if self
            .ecn_end
            .is_some_and(|end| ack.serial_cmp(end) == Some(Ordering::Greater))
        {
            self.ecn_end = None;
        }
        if self.ecn_end.is_none() {
            self.reduce_threshold(flight);
        }
        self.tlp_reduction_end = Some(highest_sent);
        self.cwnd = self.cwnd.min(self.ssthresh);
        self.acknowledged = 0;
        self.reset_duplicate_acks();
        true
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Recovery/ECN/TLP epochs prevent repeated original-flight reductions; retransmission losses use a separate additional response.
    //# If multiple original transmissions or retransmissions were lost in a
    //# window, the congestion control specified in [RFC5681] only reacts
    //# once per window.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= reason=Enhanced SACK recovery target halves eligible flight with two-MSS floor; sack_entry_partial_and_full_ack asserts 8000 -> 4000 and minimum case. Negotiated SACK/non-RACK and RACK lost-retransmission responses separately tested; ECN shared epoch is distinct policy.
    //# That is, when the first loss in a window of data is detected, ssthresh MUST be set to no
    //# more than the value given by equation (4).
    pub(crate) fn on_sack_recovery(&mut self, ack: Seq, flight: u32, highest_sent: Seq) -> bool {
        if self.sack_recovery
            || self.fast_recovery
            || self.recover.is_some_and(|end| {
                !matches!(
                    ack.serial_cmp(end),
                    Some(Ordering::Equal | Ordering::Greater)
                )
            })
        {
            return false;
        }
        if self
            .ecn_end
            .is_some_and(|end| ack.serial_cmp(end) == Some(Ordering::Greater))
        {
            self.ecn_end = None;
        }
        if self.ecn_end.is_none()
            && self
                .tlp_reduction_end
                .is_none_or(|end| ack.serial_cmp(end) == Some(Ordering::Greater))
        {
            self.reduce_threshold(flight);
        }
        self.recover = Some(highest_sent);
        self.sack_recovery = true;
        self.fast_recovery = false;
        self.cwnd = self.ssthresh;
        self.acknowledged = 0;
        self.reset_duplicate_acks();
        true
    }

    pub(crate) fn in_fast_recovery(&self) -> bool {
        self.fast_recovery
    }

    pub(crate) fn in_recovery(&self) -> bool {
        self.sack_recovery || self.fast_recovery
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Additional loss response reduces threshold from bounded current cwnd/threshold rather than unchanged cumulative flight.
    //# In the absence of PRR [RFC6937], when RACK-TLP detects a lost
    //# retransmission, the congestion control MUST trigger an additional
    //# congestion response per the aforementioned principle in [RFC5681].
    pub(crate) fn retransmission_lost(&mut self, flight: u32) {
        // A new loss of a retransmission is additional congestion, not another
        // reduction of the unchanged original cumulative flight. Exclude Reno
        // inflation and respect any previous loss/ECN window reduction.
        self.reduce_threshold(flight.min(self.cwnd).min(self.ssthresh));
        self.cwnd = self.cwnd.min(self.ssthresh);
        self.ecn_end = None;
        self.tlp_reduction_end = None;
    }

    pub(crate) fn cancel_prr_recovery(&mut self) {
        self.fast_recovery = false;
        self.cancel_sack_recovery();
    }

    pub(crate) fn cancel_sack_recovery(&mut self) {
        self.sack_recovery = false;
        self.acknowledged = 0;
    }

    // The caller checks RFC 5681's duplicate-ACK eligibility conditions.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# When in fast recovery, this variable records the send sequence number that must be
    //# acknowledged before the fast recovery procedure is declared to be over.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
    //= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
    //# The NewReno modification applies to the fast recovery procedure that begins when three
    //# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
    //# ACK arrives that acknowledges all of the data up to and including the data that was
    //# outstanding when the fast recovery procedure began.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# The procedures specified in Section 3.2 of [RFC5681] are followed, with the
    //# modifications listed below.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# When the third duplicate ACK is received, the TCP sender first checks the value of
    //# recover to see if the Cumulative Acknowledgment field covers more than recover. If so,
    //# the value of recover is incremented to the value of the highest sequence number
    //# transmitted by the TCP so far. The TCP then enters fast retransmit (step 2 of Section
    //# 3.2 of [RFC5681]). If not, the TCP does not enter fast retransmit and does not reset
    //# ssthresh.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# Do not exit the fast recovery procedure (i.e., if any duplicate ACKs subsequently
    //# arrive, execute step 4 of Section 3.2 of [RFC5681]).
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# Because the acknowledgment field contains the sequence number that the sender next
    //# expects to receive, the acknowledgment "ack_number" covers more than recover when
    //# ack_number - 1 > recover; i.e., at least one byte more of data is acknowledged beyond
    //# the highest byte that was outstanding when fast retransmit was last entered.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# This document also does not address issues of adjusting the duplicate acknowledgment
    //# threshold, but assumes the threshold specified in the IETF standards; the current
    //# standard is [RFC5681], which specifies a threshold of three duplicate acknowledgments.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-4
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# For a TCP sender that implements the algorithm specified in Section 3.2 of this
    //# document, the sender does not infer a packet drop from duplicate acknowledgments in
    //# this scenario. As always, the retransmit timer is the backup mechanism for inferring
    //# packet loss in this case.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# An implementation may want to use a separate flag to record whether or not it is
    //# presently in the fast recovery procedure.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# The use of the value of the duplicate acknowledgment counter for this purpose is not
    //# reliable, because it can be reset upon window updates and out-of- order
    //# acknowledgments.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# Entry into fast recovery is only possible when the Cumulative Acknowledgment field
    //# covers more than the state variable recover.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# When updating the Cumulative Acknowledgment field outside of fast recovery, the state
    //# variable recover may also need to be updated in order to continue to permit possible
    //# entry into fast recovery (Section 3.2, step 2). This issue arises when an update of
    //# the Cumulative Acknowledgment field results in a sequence wraparound that affects the
    //# ordering between the Cumulative Acknowledgment field and the state variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Three eligible duplicate ACKs enter only after initial NewReno and retained loss guards permit; stores exclusive highest_sent. Existing ECN/loss epochs may conservatively retain ssthresh.
    //# When three or more duplicate acknowledgments are received, the Cumulative
    //# Acknowledgment field doesn't cover more than recover, and a new fast recovery is not
    //# invoked, the sender should follow the guidance in Section 4.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-SACK Reno/NewReno fallback uses three eligible duplicate ACKs without RTO backoff; wire trace asserts retransmission of SND.UNA payload. Negotiated SACK/RACK loss inference is separately RFC6675/8985, not this fallback test.
    //# The TCP sender SHOULD use the "fast retransmit" algorithm to detect and repair loss,
    //# based on incoming duplicate ACKs.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-ECE non-SACK Reno/NewReno fast entry: helper asserts cwnd=ssthresh+3SMSS (7000=4000+3000); wire test asserts SND.UNA retransmission. Negotiated SACK/RACK/PRR instead follow section4.3 modified recovery and do not use Reno inflation.
    //# The lost segment starting at SND.UNA MUST be retransmitted and cwnd set to ssthresh plus
    //# 3*SMSS.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= reason=Non-ECE non-SACK fast recovery only: helper fourth DupACK raises 7000 to 8000 at MSS1000; accepted ECE instead follows RFC3168 no-growth policy. Negotiated SACK/RACK/PRR do not artificially inflate cwnd; see section4.3 obligations.
    //# For each additional duplicate ACK received (after the third), cwnd MUST be incremented
    //# by SMSS.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=Negotiated non-SACK Reno/NewReno: ecn_duplicate_and_advancing_ack_growth_boundaries asserts entry/later duplicate-ECE suppression and advancing/non-ECE contrasts; ecn_duplicate_entry_below_threshold_and_covering_ack_exit traces successive reductions to cwnd<ssthresh, capped ECE entry and covering-ECE exit, normal non-ECE exit and preserved wire retransmission. No general inherited recovery-compliance claim.
    //# The sending
    //# TCP SHOULD NOT increase the congestion window in response to the
    //# receipt of an ECN-Echo ACK packet.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Initial guard clears on first validated progress beyond ISS+1; loss guard clears on first bounded cumulative advancement beyond recorded end. Ten bounded sub-half-space controller advancements span more than a full sequence cycle without stale initial state; existing timeout_marker_boundaries_and_wrap and integrated epoch tests assert loss-guard equality and wrapping entry.
    //# When updating the Cumulative Acknowledgment field outside of fast recovery, the state variable
    //# recover may also need to be updated in order to continue to permit possible entry into fast
    //# recovery (Section 3.2, step 2). This issue arises when an update of the Cumulative
    //# Acknowledgment field results in a sequence wraparound that affects the ordering between the
    //# Cumulative Acknowledgment field and the state variable recover.
    pub(crate) fn observe_ack(&mut self, ack: Seq) {
        if self
            .initial_recover
            .is_some_and(|end| ack.serial_cmp(end) == Some(Ordering::Greater))
        {
            // Clear on the first bounded advancement; never retain a stale ISS
            // across half-space or subsequent sequence wraps.
            self.initial_recover = None;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=No-SACK NewReno RFC5681 section3.2 layer: duplicate_ack_eligibility_and_intervening_advancement_reset, limited_transmit_is_one_packet_per_duplicate_and_excluded_from_threshold, fourth_duplicate_grants_fresh_mss_only_with_both_windows and wire partial/exit traces assert eligibility, exclusions, inflation and bounded output. Initial guard and zero partial deflation have dedicated tests; this is not a global enhanced-PRR/half-flight assertion.
    //# The procedures specified in Section 3.2 of [RFC5681] are followed, with the modifications
    //# listed below.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Real initial and retained loss-epoch third-duplicate suppression leaves threshold unchanged; cumulative progress beyond the boundary resets duplicates and admits entry. Active-recovery RTO and guarded duplicates also asserted. ECN shared epochs remain covered by existing tests.
    //# When the third duplicate ACK is received, the TCP sender first checks the value of recover to
    //# see if the Cumulative Acknowledgment field covers more than recover. If so, the value of
    //# recover is incremented to the value of the highest sequence number transmitted by the TCP so
    //# far. The TCP then enters fast retransmit (step 2 of Section 3.2 of [RFC5681]). If not, the TCP
    //# does not enter fast retransmit and does not reset ssthresh.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=Initial ISS+1 and loss-epoch exclusive end both require strictly greater cumulative ACK for NewReno. Equality suppression, later-byte entry, timeout and wrap are asserted by integrated traces and initial_recover_boundaries_and_long_bounded_progress.
    //# Because the acknowledgment field contains the sequence number that the sender next expects to
    //# receive, the acknowledgment "ack_number" covers more than recover when ack_number - 1 >
    //# recover; i.e., at least one byte more of data is acknowledged beyond the highest byte that was
    //# outstanding when fast retransmit was last entered.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Initial ISS+1 and loss-epoch exclusive end both require strictly greater cumulative ACK for NewReno. Equality suppression, later-byte entry, timeout and wrap are asserted by integrated traces and initial_recover_boundaries_and_long_bounded_progress.
    //# Entry into fast recovery is only possible when the Cumulative Acknowledgment field covers more
    //# than the state variable recover.
    pub(crate) fn on_duplicate_ack(
        &mut self,
        ack: Seq,
        flight: u32,
        highest_sent: Seq,
        ece: bool,
    ) -> bool {
        self.observe_ack(ack);
        if self.sack_recovery {
            return false;
        }
        if self.fast_recovery {
            if !ece {
                self.cwnd = self.cwnd.saturating_add(self.mss).min(MAX_WINDOW);
            }
            return false;
        }
        self.duplicate_acks = self.duplicate_acks.saturating_add(1);
        if self.duplicate_acks != 3
            || self.recover.is_some()
            || self.algorithm == RecoveryAlgorithm::NewReno && self.initial_recover.is_some()
        {
            return false;
        }
        if self.ecn_end.is_none() && self.tlp_reduction_end.is_none() {
            self.reduce_threshold(flight);
        }
        let inflated = self
            .ssthresh
            .saturating_add(self.mss.saturating_mul(3))
            .min(MAX_WINDOW);
        self.cwnd = if ece {
            self.cwnd.min(inflated)
        } else {
            inflated
        };
        self.recover = Some(highest_sent);
        self.fast_recovery = true;
        self.acknowledged = 0;
        true
    }

    // A separate ECN epoch must not suppress fast retransmission of real losses.
    // Loss recovery and ECN share the threshold reduction, not retransmit state.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5
    //= reason=TCP sender reduction only: helper asserts cwnd/threshold reduction, mixed loss/ECN epoch and no duplicate response; connection asserts repeated ECE and no ECN-driven retransmission. Generic non-TCP transports are not provided.
    //# Upon the receipt by an ECN-Capable transport of a single CE packet,
    //# the congestion control algorithms followed at the end-systems MUST be
    //# essentially the same as the congestion control response to a *single*
    //# dropped packet.
    // Actor/condition: TCP sender/congestion controller; single CE indication in eligible original-flight epoch.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=Negotiated non-SACK Reno/NewReno: ecn_duplicate_and_advancing_ack_growth_boundaries asserts entry/later duplicate-ECE suppression and advancing/non-ECE contrasts; ecn_duplicate_entry_below_threshold_and_covering_ack_exit traces successive reductions to cwnd<ssthresh, capped ECE entry and covering-ECE exit, normal non-ECE exit and preserved wire retransmission. No general inherited recovery-compliance claim.
    //# The sending
    //# TCP SHOULD NOT increase the congestion window in response to the
    //# receipt of an ECN-Echo ACK packet.
    // Actor/condition: TCP sender/congestion controller; accepted ECE ACK.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=Reno/NewReno helper epoch/threshold assertions plus connection emitted-retransmission-versus-pending-loss RTO assertions. No router congestion-detection claim.
    //# TCP should not react to congestion indications more than once every window of data (or more loosely, more than once every round-trip time). That is, the TCP sender's congestion window should be reduced only once in response to a series of dropped and/or CE packets from a single window of data. In addition, the TCP source should not decrease the slow-start threshold, ssthresh, if it has been decreased within the last round trip time. However, if any retransmitted packets are dropped, then this is interpreted by the source TCP as a new instance of congestion.
    // Actor/condition: TCP endpoint; mixed ECN/loss epoch and lost retransmission.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5
    //= reason=Original-flight reduction epoch assertions combine ECN and actual loss; retransmission loss remains a new event, as refined in section 6.1.2.
    //# An additional goal is that the end-systems should react to congestion at most once per window of data (i.e., at most once per round-trip time), to avoid reacting multiple times to multiple indications of congestion within a round-trip time.
    // Actor/condition: TCP endpoint; multiple indications within original-flight epoch.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= reason=Congestion helper asserts cwnd/threshold values after eligible ECN and mixed-loss epochs; one-MSS timer rate reduction is separately audited.
    //# That is, the TCP source halves the congestion window "cwnd" and reduces the slow start threshold "ssthresh".
    // Actor/condition: TCP endpoint; eligible ECE ACK.
    pub(crate) fn on_ecn(&mut self, ack: Seq, flight: u32, highest_sent: Seq) -> bool {
        if self
            .tlp_reduction_end
            .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
            || self
                .ecn_end
                .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
            || self
                .recover
                .is_some_and(|end| ack.serial_cmp(end) != Some(Ordering::Greater))
        {
            return false;
        }
        self.reduce_threshold(flight);
        // RFC 9438 section 4.6 permits CUBIC's beta=0.7 instead of the
        // RFC 5681/RFC 3168 default Reno half reduction. ECN still reaches one MSS independently
        // of the two-MSS ssthresh floor and shares the existing epoch guards.
        let reduced = if self.cubic.is_some() {
            (u64::from(flight) * 7 / 10).min(u64::from(self.cwnd)) as u32
        } else {
            self.cwnd / 2
        };
        self.cwnd = reduced.max(self.mss).min(self.ssthresh);
        self.acknowledged = 0;
        self.ecn_end = Some(highest_sent);
        true
    }

    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Default CongestionAlgorithm::Reno only; optional CUBIC follows RFC9438 sections 4.6/4.8. Threshold helper uses actual eligible flight /2 with two-MSS minimum; timeout vectors assert 10000->5000 and SACK boundary vectors assert floor. Limited Transmit exclusion is caller-owned and separately evidenced.
    //# ssthresh = max (FlightSize / 2, 2*SMSS) (4)
    fn reduce_threshold(&mut self, flight: u32) {
        // Optional RFC 9438 sections 4.6/4.8 are the scoped exception to
        // RFC 5681's half-flight threshold, not a recovery-algorithm change.
        let reduced = if let Some(cubic) = &mut self.cubic {
            cubic.congestion(self.cwnd);
            (u64::from(flight) * 7 / 10) as u32
        } else {
            flight / 2
        };
        self.ssthresh = reduced.max(self.mss.saturating_mul(2)).min(MAX_WINDOW);
    }

    // Called only after successful output, not when retransmission is scheduled.
    // Retain the furthest end, including arbitrary SACK ranges: a cumulative ACK
    // covering it covers all retransmissions (live spans must remain below 2^31).
    // This conservatively tracks unacknowledged retransmissions, not SACK delivery.
    pub(crate) fn on_retransmit(&mut self, end: Seq) {
        if self
            .retransmitted_end
            .is_none_or(|old| end.serial_cmp(old) == Some(Ordering::Greater))
        {
            self.retransmitted_end = Some(end);
        }
    }

    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
    //= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
    //# The NewReno modification applies to the fast recovery procedure that begins when three
    //# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
    //# ACK arrives that acknowledges all of the data up to and including the data that was
    //# outstanding when the fast recovery procedure began.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= reason=on_timeout stores exclusive highest_sent and clears recovery; timeout_marker_boundaries_and_wrap directly asserts active flag clear and marker replacement. newreno_partial_ack_wire_timer_and_exit_boundaries asserts active wire RTO at exact expiry.
    //# After a retransmit timeout, record the highest sequence number transmitted in the
    //# variable recover, and exit the fast recovery procedure if applicable.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-4
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //# After each retransmit timeout, the highest sequence number transmitted so far is
    //# recorded in the variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-4
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //# For a TCP sender that implements the algorithm specified in Section 3.2 of this
    //# document, the sender does not infer a packet drop from duplicate acknowledgments in
    //# this scenario. As always, the retransmit timer is the backup mechanism for inferring
    //# packet loss in this case.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Stores exclusive highest_sent, exits both recovery flags, sets cwnd=MSS, resets duplicate count.
    //# When three or more duplicate acknowledgments are received, the Cumulative
    //# Acknowledgment field doesn't cover more than recover, and a new fast recovery is not
    //# invoked, the sender should follow the guidance in Section 4.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=on_timeout halves supplied FlightSize with two-MSS floor on first timeout; repeated same-segment timeout keeps threshold. Helper asserts 10000 flight -> 5000 threshold, repeat at flight=2000 -> unchanged 5000; minimum floor separately asserted by sack_timeout_boundary_and_cancel_preserve_epoch. ECN sharing is a separate RFC3168 policy.
    //# When a TCP sender detects segment loss using the retransmission timer and the given
    //# segment has not yet been resent by way of the retransmission timer, the value of
    //# ssthresh MUST be set to no more than the value given in equation (4):
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Both Reno/NewReno and default/IW10 retain a one-effective-MSS loss window. Helper verifies cwnd reset and ACK-driven transition; IW10 wire test asserts exactly one retransmission and no second output.
    //# Furthermore, upon a timeout (as specified in [RFC2988]) cwnd MUST be set to no more than
    //# the loss window, LW, which equals 1 full-sized segment (regardless of the value of IW).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= reason=Repeated RTO for the same outstanding head retains ssthresh; timeout_marker_boundaries_and_wrap asserts threshold remains5000 after smaller-flight second timeout and resets for a new acknowledged flight. Caller timer/encode atomicity is separate.
    //# On the other hand, when a TCP sender detects segment loss using the retransmission timer
    //# and the given segment has already been retransmitted by way of the retransmission timer
    //# at least once, the value of ssthresh is held constant.
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=IW10 loss window remains one effective MSS; helper and wire trace assert timeout reduction, one retransmit and denied next output.
    //# These changes do NOT change the loss window, which must remain 1 segment of MSS bytes
    //# (to permit the lowest possible window size in the case of severe congestion).
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
    //= reason=Endpoint corrupts the checksum of actual ECT data and submits it with CE; receiver drops without feedback or bytes. Sender timeout reduces cwnd and retransmits that same sequence/payload Not-ECT without CWR.
    //# Similarly, if a CE packet is dropped later in the network due to corruption (bit errors), the end nodes should still invoke congestion control, just as TCP would today in response to a dropped data packet.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= reason=Ordinary Reno/NewReno wire retransmissions, successive flights and wrap assert both window/threshold reductions; lost-fast-retransmission RTO uses bounded prior threshold rather than unchanged flight. Repeat RTO retains threshold. RACK lost-retransmission response is separately asserted in rack_replacement_loss_renews_response_without_cumulative_progress.
    //# Loss in two successive windows of data, or the loss of a retransmission, should be taken as two
    //# indications of congestion and, therefore, cwnd (and ssthresh) MUST be lowered twice in this
    //# case.
    pub(crate) fn on_timeout(&mut self, flight: u32, highest_sent: Seq) {
        // Repeated RTOs for the same unacknowledged segment retain ssthresh.
        // RFC 3168 section 6.1.2: loss of a retransmission is new congestion,
        // even inside the ECN epoch. An original-flight loss shares its reduction.
        if !self.timeout_retransmitted
            && ((self.ecn_end.is_none() && self.tlp_reduction_end.is_none())
                || self.retransmitted_end.is_some())
        {
            let flight = if self.retransmitted_end.is_some() {
                // Loss of a fast/SACK retransmission is a second congestion
                // event; unchanged cumulative flight must not undo the first.
                flight.min(self.cwnd).min(self.ssthresh)
            } else {
                flight
            };
            self.reduce_threshold(flight);
        }
        if let Some(cubic) = &mut self.cubic {
            cubic.timeout();
        }
        self.ecn_end = None;
        self.tlp_reduction_end = None;
        self.timeout_retransmitted = true;
        self.recover = Some(highest_sent);
        self.fast_recovery = false;
        self.sack_recovery = false;
        self.cwnd = self.mss;
        self.congestion_avoidance = false;
        self.acknowledged = 0;
        self.reset_duplicate_acks();
    }

    pub(crate) fn reset_duplicate_acks(&mut self) {
        self.duplicate_acks = 0;
    }

    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= reason=Selected IW10 restart choice uses min(current cwnd, IW10); helper covers grown and reduced cwnd and changing MSS, and wire idle trace asserts burst limited to ten MSS. iw10_transmit_idle_restart_and_data_rto covers the last-data idle trigger despite received requests and emitted pure ACKs; this evidence is the optional window value only.
    //# Optionally, a TCP MAY set the restart window to the minimum of the value used for the
    //# initial window and the current value of cwnd (in other words, using a larger value for
    //# the restart window should never increase the size of cwnd).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.1
    //= reason=restart_after_idle sets min(cwnd,selected IW), never increases a reduced cwnd; both algorithm choices assert reduced and grown values. iw10_transmit_idle_restart_and_data_rto covers the last-data idle trigger; default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss cover default IW calculation.
    //# For the purposes of this standard, we define RW = min(IW,cwnd).
    pub(crate) fn limit_restart(&mut self, window: u32) {
        self.cwnd = self.cwnd.min(window);
    }

    pub(crate) fn restart_after_idle(&mut self) {
        if let Some(cubic) = &mut self.cubic {
            cubic.restart();
        }
        self.cwnd = self.cwnd.min(self.initial_window());
        self.acknowledged = 0;
        self.reset_duplicate_acks();
    }
}

// RFC 9937 section 6, byte units; selection is composed by Connection.
// Sending policy only: data selection is composed separately by Connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrrAlgorithm {
    #[default]
    Rfc9937,
    // Historical unconditional entry MSS, deferred ACK replay and persist bypass.
    // Compatibility policy, not a claim of RFC 6937 or RFC 9937 conformance.
    LegacyInitialCredit,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Prr {
    algorithm: PrrAlgorithm,
    recover_fs: u32,
    mss: u32,
    dupack_bytes: u32,
    delivered: u64,
    out: u64,
    credit: u32,
}

impl Prr {
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
    //# At the beginning of a congestion control response episode initiated
    //# by the congestion control algorithm, a data sender using PRR MUST
    //# initialize the PRR state.
    pub(crate) fn new(flight: u32, mss: u32, algorithm: PrrAlgorithm) -> Self {
        Self {
            algorithm,
            recover_fs: if algorithm == PrrAlgorithm::LegacyInitialCredit {
                flight.max(1)
            } else {
                flight
            },
            mss,
            dupack_bytes: 0,
            delivered: 0,
            out: 0,
            credit: if algorithm == PrrAlgorithm::LegacyInitialCredit {
                mss
            } else {
                0
            },
        }
    }

    // RFC 9937 §6.1: ACK-driven initialization includes this ACK's delivery.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
    //= reason=include_entry_delivery is called only for ACK-driven new episodes; later ACKs leave the denominator fixed. A new congestion response completes and replaces the old episode, not a mutation of its denominator.
    //# Upon entering fast
    //# recovery, PRR initializes RecoverFS, and RecoverFS remains constant
    //# during a given fast recovery episode.
    pub(crate) fn include_entry_delivery(&mut self, delivered: u32) {
        self.recover_fs = self.recover_fs.saturating_add(delivered);
    }

    pub(crate) fn set_mss(&mut self, mss: u32) {
        self.mss = mss;
    }

    // RFC 9937 §6.2: estimates are deducted on cumulative progress and bounded
    // by the fixed episode flight, even for extraneous duplicate ACKs.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Duplicate estimates are deducted across partial cumulative progress; no-SACK wire trace asserts current entry duplicate, short retransmit, zero-delivery ACK and final completion. No obsolete SACK-only exemption.
    //# In recovery without SACK,
    //# DeliveredData is estimated to be 1 SMSS on each received duplicate
    //# ACK (i.e., SND.UNA did not change).  When SND.UNA advances (i.e., a
    //# full or partial ACK), DeliveredData is the change in SND.UNA, minus 1
    //# SMSS for each preceding duplicate ACK.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Repeated extraneous duplicates cannot increase delivered above 10000-byte episode RecoverFS; capped ACK preserves counters, credit and cwnd, through wrap.
    //# As a mitigation, if not using SACK, then PRR
    //# disallows incrementing DeliveredData when the total bytes delivered
    //# in a PRR episode would exceed the estimated data outstanding upon
    //# entering recovery (RecoverFS).
    pub(crate) fn non_sack_delivery(&mut self, cumulative: u32, duplicate: bool) -> u32 {
        let delivered = if cumulative != 0 {
            let delivered = cumulative.saturating_sub(self.dupack_bytes);
            self.dupack_bytes = self.dupack_bytes.saturating_sub(cumulative);
            delivered
        } else if duplicate {
            self.dupack_bytes = self
                .dupack_bytes
                .saturating_add(self.mss)
                .min(self.recover_fs);
            self.mss
        } else {
            0
        };
        delivered.min(
            self.recover_fs
                .saturating_sub(self.delivered.min(u64::from(u32::MAX)) as u32),
        )
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Subtracts capped duplicate-delivery estimate from the lost/retransmitted payload ledger; wire integration additionally asserts committed partial retransmission pipe and delivery cap in rfc9937_no_sack_wire_delivery_cap_zero_ack_and_completion.
    //# For non-SACK-enabled connections,
    //# instead of subtracting out bytes SACKed in the SACK scoreboard,
    //# senders MUST subtract out: min(RecoverFS, 1 SMSS for each preceding
    //# duplicate ACK in the fast recovery episode); the min() with RecoverFS
    //# is to protect against misbehaving receivers [Savage99].
    pub(crate) fn non_sack_pipe(&self, pipe_without_delivery_estimates: u32) -> u32 {
        pipe_without_delivery_estimates.saturating_sub(self.dupack_bytes.min(self.recover_fs))
    }

    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Rfc9937 accounts current delivery, inflight and SafeACK against a fixed episode target; LegacyInitialCredit is compatibility-only.
    //# The Proportional Rate
    //# Reduction (PRR) algorithm [RFC6937] is RECOMMENDED for the specific
    //# congestion control actions taken upon the losses detected by RACK-
    //# TLP.
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Rfc9937 only; LegacyInitialCredit deliberately retains historical equations.
    //# if (DeliveredData is 0)
    //#    Return
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Byte counters accumulate current ACK only; independent per-ACK oracle and wire traces cover signed SACK trimming and no-SACK capped delivery.
    //# prr_delivered += DeliveredData
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Widened byte multiplication with ceil division; threshold equality selects reduction branch. Large integer overflow vector in rfc9937_safe_unsafe_zero_delivery_and_forced_first_transmit and independent wire oracle supplement the vectors; legacy equation tests are not used.
    //# if (inflight > ssthresh) {
    //#    // Proportional Rate Reduction
    //#    // This uses integer division, rounding up:
    //#    #define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
    //#    out = DIV_ROUND_UP(prr_delivered * ssthresh, RecoverFS)
    //#    SndCnt = out - prr_out
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Current-delivery MAX, optional safe SMSS and target headroom are directly asserted after prior forced output; unsafe/safe values differ by one MSS. Connection SafeACK input evidence gap is tracked separately, not waived here.
    //# } else {
    //#    // PRR-CRB by default
    //#    SndCnt = MAX(prr_delivered - prr_out, DeliveredData)
    //#    if (SafeACK) {
    //#       // PRR-SSRB when recovery is making good progress
    //#       SndCnt += SMSS
    //#    }
    //#    // Attempt to catch up, as permitted
    //#    SndCnt = MIN(ssthresh - inflight, SndCnt)
    //# }
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= reason=Nonzero delivery only; failure consumes nothing, successful short output prevents another floor. This test injects the equation state then exercises real transactional output; zero-delivery timer entry is independently tested to remain zero.
    //# if (prr_out is 0 AND SndCnt is 0) {
    //#    // Force a fast retransmit upon entering recovery
    //#    SndCnt = SMSS
    //# }
    //= https://www.rfc-editor.org/rfc/rfc9937#section-13
    //= reason=PRR counts bytes, not segments: 137-byte ACKs/97-byte committed output, ceil rounding and zero duplicates are asserted. No assertion of universal malicious-receiver security; no-SACK artificial delivery is independently capped.
    //# Implementers that change PRR from counting bytes to segments have to
    //# be cautious about the effects of ACK splitting attacks [Savage99],
    //# where the receiver acknowledges partial segments for the purpose of
    //# confusing the sender's congestion accounting.
    pub(crate) fn acknowledge(
        &mut self,
        delivered: u32,
        pipe: u32,
        threshold: u32,
        safe_ack: bool,
    ) {
        let modern = self.algorithm == PrrAlgorithm::Rfc9937;
        if modern && delivered == 0 {
            return;
        }
        self.delivered = self.delivered.saturating_add(u64::from(delivered));
        let credit = if pipe > threshold {
            let allowed = (u128::from(self.delivered) * u128::from(threshold))
                .div_ceil(u128::from(self.recover_fs.max(1)))
                .min(u128::from(u64::MAX));
            (allowed as u64).saturating_sub(self.out)
        } else if modern {
            self.delivered
                .saturating_sub(self.out)
                .max(u64::from(delivered))
                .saturating_add(if safe_ack { u64::from(self.mss) } else { 0 })
                .min(u64::from(threshold - pipe))
        } else {
            self.delivered
                .saturating_sub(self.out)
                .min(u64::from(threshold - pipe))
        };
        self.credit = credit.min(u64::from(u32::MAX)) as u32;
        if modern && self.out == 0 && self.credit == 0 {
            self.credit = self.mss;
        }
    }

    // Entry policy, not an RFC 6937 CRB equation: this may permit out > delivered.
    // Strict mode never applies this compatibility override.
    pub(crate) fn guarantee_initial(&mut self, mss: u32) {
        if self.algorithm == PrrAlgorithm::LegacyInitialCredit {
            self.credit = self.credit.max(mss);
        }
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> (u32, u64, u64) {
        (self.recover_fs, self.delivered, self.out)
    }

    pub(crate) fn credit(&self) -> u32 {
        self.credit
    }

    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.3
    //# On any data transmission or retransmission, PRR executes the
    //# following:
    //#
    //#    prr_out += (data sent)
    pub(crate) fn sent(&mut self, bytes: u32) {
        if self.algorithm == PrrAlgorithm::Rfc9937 {
            debug_assert!(bytes <= self.credit);
        }
        self.out = self.out.saturating_add(u64::from(bytes));
        self.credit = self.credit.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= type=test
    //= reason=Rfc9937 only: zero delivery retains prior counters and credit despite changed pipe; Connection retains PRR cwnd on ordinary zero-delivery ACKs. No first-transmit override before this return.
    //# if (DeliveredData is 0)
    //#    Return
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= type=test
    //= reason=Current-delivery MAX, optional safe SMSS and target headroom are directly asserted after prior forced output; unsafe/safe values differ by one MSS. Connection SafeACK input evidence gap is tracked separately, not waived here.
    //# } else {
    //#    // PRR-CRB by default
    //#    SndCnt = MAX(prr_delivered - prr_out, DeliveredData)
    //#    if (SafeACK) {
    //#       // PRR-SSRB when recovery is making good progress
    //#       SndCnt += SMSS
    //#    }
    //#    // Attempt to catch up, as permitted
    //#    SndCnt = MIN(ssthresh - inflight, SndCnt)
    //# }
    fn rfc9937_safe_unsafe_zero_delivery_and_forced_first_transmit() {
        let mut empty_after_ack = Prr::new(0, 1000, PrrAlgorithm::Rfc9937);
        empty_after_ack.include_entry_delivery(1000);
        assert_eq!(empty_after_ack.counters(), (1000, 0, 0));
        for safe in [false, true] {
            let mut p = Prr::new(10_000, 1000, PrrAlgorithm::Rfc9937);
            p.acknowledge(1, 5000, 5000, safe);
            assert_eq!(p.credit(), 1000); // Force only when the computed count is zero.
            let before = p.counters();
            p.acknowledge(0, 0, 5000, true);
            assert_eq!(p.counters(), before);
            assert_eq!(p.credit(), 1000); // Failed output / changed estimator cannot revoke it.
            p.sent(1000);
            p.acknowledge(1000, 1000, 5000, safe);
            assert_eq!(p.credit(), if safe { 2000 } else { 1000 }); // MAX includes current delivery.
            p.sent(p.credit());
            p.acknowledge(1000, 5000, 5000, safe);
            assert_eq!(p.credit(), 0); // No forced SMSS after any committed output.
        }
        let mut p = Prr::new(u32::MAX, 1000, PrrAlgorithm::Rfc9937);
        p.acknowledge(u32::MAX, u32::MAX, u32::MAX - 1, false);
        assert_eq!(p.credit(), u32::MAX - 1); // Widen before multiplication / rounding.
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= type=test
    //= reason=Subtracts capped duplicate-delivery estimate from the lost/retransmitted payload ledger; wire integration additionally asserts committed partial retransmission pipe and delivery cap in rfc9937_no_sack_wire_delivery_cap_zero_ack_and_completion.
    //# For non-SACK-enabled connections,
    //# instead of subtracting out bytes SACKed in the SACK scoreboard,
    //# senders MUST subtract out: min(RecoverFS, 1 SMSS for each preceding
    //# duplicate ACK in the fast recovery episode); the min() with RecoverFS
    //# is to protect against misbehaving receivers [Savage99].
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= type=test
    //= reason=Duplicate estimates are deducted across partial cumulative progress; no-SACK wire trace asserts current entry duplicate, short retransmit, zero-delivery ACK and final completion. No obsolete SACK-only exemption.
    //# In recovery without SACK,
    //# DeliveredData is estimated to be 1 SMSS on each received duplicate
    //# ACK (i.e., SND.UNA did not change).  When SND.UNA advances (i.e., a
    //# full or partial ACK), DeliveredData is the change in SND.UNA, minus 1
    //# SMSS for each preceding duplicate ACK.
    fn rfc9937_non_sack_estimates_cap_delivery_and_deduct_prior_duplicates() {
        let mut p = Prr::new(5000, 1000, PrrAlgorithm::Rfc9937);
        for i in 1..=2 {
            let d = p.non_sack_delivery(0, true);
            assert_eq!(d, 1000);
            let pipe = p.non_sack_pipe(4000);
            assert_eq!(pipe, 5000 - i * 1000 - 1000);
            p.acknowledge(d, pipe, 2500, false);
        }
        assert_eq!(p.non_sack_delivery(1500, false), 0);
        assert_eq!(p.non_sack_pipe(3500), 3000);
        assert_eq!(p.non_sack_delivery(1000, false), 500);
        p.acknowledge(500, 2500, 2500, false);
        for _ in 0..20 {
            let d = p.non_sack_delivery(0, true);
            p.acknowledge(d, p.non_sack_pipe(2500), 2500, false);
        }
        assert_eq!(p.counters().1, 5000);
        assert_eq!(p.non_sack_delivery(5000, false), 0);
        assert_eq!(p.non_sack_pipe(0), 0);
    }

    #[test]
    fn caller_units_estimator_policy_bounds_and_tick_precision() {
        for scale in [1, 1000] {
            let timebase = crate::connection::CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..crate::connection::CallerTimebase::default()
            };
            let mut rtt = RttEstimator::with_timebase(200_000, timebase);
            assert_eq!(rtt.rto(), 1_000_000 * scale);
            rtt.sample(100_000 * scale);
            assert_eq!(rtt.rto(), 300_000 * scale);
            for _ in 0..32 {
                rtt.backoff();
            }
            assert_eq!(rtt.rto(), 60_000_000 * scale);
            rtt.sample(u64::MAX);
            assert_eq!(rtt.rto(), 60_000_000 * scale);
            let mut tiny = RttEstimator::with_timebase(1, timebase);
            tiny.sample(1);
            assert_eq!(tiny.srtt(), Some(1));
            assert_eq!(tiny.rto(), 1 + 1000 * scale);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Initial guard clears on first validated progress beyond ISS+1; loss guard clears on first bounded cumulative advancement beyond recorded end. Ten bounded sub-half-space controller advancements span more than a full sequence cycle without stale initial state; existing timeout_marker_boundaries_and_wrap and integrated epoch tests assert loss-guard equality and wrapping entry.
    //# When updating the Cumulative Acknowledgment field outside of fast recovery, the state variable
    //# recover may also need to be updated in order to continue to permit possible entry into fast
    //# recovery (Section 3.2, step 2). This issue arises when an update of the Cumulative
    //# Acknowledgment field results in a sequence wraparound that affects the ordering between the
    //# Cumulative Acknowledgment field and the state variable recover.
    fn initial_recover_boundaries_and_long_bounded_progress() {
        for iss in [Seq(100), Seq(u32::MAX - 1), Seq(u32::MAX)] {
            for ack in [iss, iss.wrapping_add(1), iss.wrapping_add(2)] {
                let mut c =
                    Congestion::new(4, RecoveryAlgorithm::NewReno, InitialWindow::default(), iss);
                assert_eq!(c.initial_recover, Some(iss.wrapping_add(1)));
                assert_eq!(c.recover, None);
                for i in 1..=3 {
                    let entered = c.on_duplicate_ack(ack, 16, iss.wrapping_add(17), false);
                    assert_eq!(entered, i == 3 && ack == iss.wrapping_add(2));
                }
                if ack != iss.wrapping_add(2) {
                    assert_eq!(c.ssthresh(), MAX_WINDOW);
                }
            }
            let mut c =
                Congestion::new(4, RecoveryAlgorithm::NewReno, InitialWindow::default(), iss);
            let mut ack = iss.wrapping_add(2);
            c.on_ack(ack, 1, 0);
            assert_eq!(c.initial_recover, None);
            // Each advancement is bounded below half-space. Progress spans more
            // than a full sequence cycle without resurrecting the stale ISS.
            for _ in 0..10 {
                ack = ack.wrapping_add(1 << 29);
                c.on_ack(ack, 1 << 29, 0);
                assert_eq!(c.initial_recover, None);
            }
            for i in 1..=3 {
                assert_eq!(
                    c.on_duplicate_ack(ack, 16, ack.wrapping_add(16), false),
                    i == 3
                );
            }
        }
    }

    #[test]
    fn partial_deflation_saturates_the_whole_signed_expression() {
        for (cwnd, acked, expected) in [(32, 36, 0), (31, 36, 0), (35, 36, 3), (2, 3, 0), (8, 4, 8)]
        {
            let mut c = Congestion::new(
                4,
                RecoveryAlgorithm::NewReno,
                InitialWindow::default(),
                Seq(0),
            );
            c.fast_recovery = true;
            c.recover = Some(Seq(100));
            c.cwnd = cwnd;
            assert!(c.on_ack(Seq(50), acked, 4));
            assert_eq!(c.cwnd(), expected);
            assert!(c.in_recovery());
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.1
    //= type=test
    //= reason=Connection selects the congestion target; constructor zeros byte counters. Entry wire traces separately assert the actual target; compatibility policy excluded.
    //# ssthresh = CongCtrlAlg()      // Target flight size in recovery
    //# prr_delivered = 0             // Total bytes delivered in recovery
    //# prr_out = 0                   // Total bytes sent in recovery
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= type=test
    //= reason=Byte counters accumulate current ACK only; independent per-ACK oracle and wire traces cover signed SACK trimming and no-SACK capped delivery.
    //# prr_delivered += DeliveredData
    //= https://www.rfc-editor.org/rfc/rfc9937#section-6.2
    //= type=test
    //= reason=Widened byte multiplication with ceil division; threshold equality selects reduction branch. Large integer overflow vector in rfc9937_safe_unsafe_zero_delivery_and_forced_first_transmit and independent wire oracle supplement the vectors; legacy equation tests are not used.
    //# if (inflight > ssthresh) {
    //#    // Proportional Rate Reduction
    //#    // This uses integer division, rounding up:
    //#    #define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
    //#    out = DIV_ROUND_UP(prr_delivered * ssthresh, RecoverFS)
    //#    SndCnt = out - prr_out
    //= https://www.rfc-editor.org/rfc/rfc9937#section-13
    //= type=test
    //= reason=PRR counts bytes, not segments: 137-byte ACKs/97-byte committed output, ceil rounding and zero duplicates are asserted. No assertion of universal malicious-receiver security; no-SACK artificial delivery is independently capped.
    //# Implementers that change PRR from counting bytes to segments have to
    //# be cautious about the effects of ACK splitting attacks [Savage99],
    //# where the receiver acknowledges partial segments for the purpose of
    //# confusing the sender's congestion accounting.
    fn rfc9937_zero_entry_and_credit_across_pipe_branches() {
        for threshold in [1000, 5000, 7000, 10_000] {
            let mut p = Prr::new(10_000, 1000, PrrAlgorithm::Rfc9937);
            assert_eq!(p.counters(), (10_000, 0, 0));
            assert_eq!(p.credit(), 0);
            p.guarantee_initial(1000);
            assert_eq!(p.credit(), 0);
            for i in 0..100 {
                // Exercise headroom discontinuities, small ACKs, duplicate ACKs,
                // banked credit and byte-accurate output without changing epochs.
                let delivered = if i % 3 == 0 { 0 } else { 137 };
                let pipe = [0, threshold - 1, threshold, threshold + 1][i % 4];
                let old_credit = p.credit();
                p.acknowledge(delivered, pipe, threshold, false);
                let mut allowed = if pipe > threshold {
                    (p.delivered * u64::from(threshold))
                        .div_ceil(10_000)
                        .saturating_sub(p.out)
                } else {
                    p.delivered
                        .saturating_sub(p.out)
                        .max(u64::from(delivered))
                        .min(u64::from(threshold - pipe))
                };
                if delivered == 0 {
                    allowed = u64::from(old_credit);
                } else if p.out == 0 && allowed == 0 {
                    allowed = 1000;
                }
                assert_eq!(u64::from(p.credit()), allowed);
                let bytes = p.credit().min(97);
                p.sent(bytes);
                assert_eq!(u64::from(p.credit()), allowed - u64::from(bytes));
            }
        }
    }

    #[test]
    fn prr_crb_proportional_conservative_bound_and_no_duplicate_credit() {
        let mut prr = Prr::new(10_000, 1000, PrrAlgorithm::Rfc9937);
        prr.acknowledge(3000, 7000, 5000, false);
        assert_eq!(prr.credit(), 1500);
        prr.sent(1000);
        assert_eq!(prr.credit(), 500);
        prr.acknowledge(1000, 3000, 5000, false);
        assert_eq!(prr.credit(), 2000);
        prr.sent(2000);
        // The two emitted MSS raise pipe from 3000 to 5000. An unchanged
        // duplicate ACK supplies no further credit at the threshold.
        prr.acknowledge(0, 5000, 5000, false);
        assert_eq!(prr.credit(), 0);
        prr.acknowledge(1000, 1000, 5000, false);
        assert_eq!(prr.credit(), 2000);
        let mut timer_entry = Prr::new(10_000, 1000, PrrAlgorithm::LegacyInitialCredit);
        timer_entry.sent(1000);
        timer_entry.acknowledge(1000, 3000, 5000, false);
        // Initial retransmission consumes actual output even without an entry ACK.
        assert_eq!(timer_entry.credit(), 0);
        let mut timer_entry = Prr::new(10_000, 1000, PrrAlgorithm::LegacyInitialCredit);
        timer_entry.acknowledge(1000, 3000, 5000, false); // Real deferred causative SACK.
        timer_entry.guarantee_initial(1000);
        timer_entry.sent(1000);
        timer_entry.acknowledge(1000, 3000, 5000, false);
        assert_eq!(timer_entry.credit(), 1000);
        timer_entry.sent(1000);
        timer_entry.acknowledge(0, 3000, 5000, false);
        assert_eq!(timer_entry.credit(), 0);
    }

    #[test]
    fn prr_duplicate_ack_preserves_banked_credit_without_minting_delivery() {
        for (pipe, expected) in [(7000, 1500), (3000, 2000)] {
            let mut prr = Prr::new(10_000, 1000, PrrAlgorithm::Rfc9937);
            prr.acknowledge(3000, pipe, 5000, false);
            assert_eq!(prr.credit(), expected);
            for _ in 0..4 {
                // also the state after repeated failed output
                prr.acknowledge(0, pipe, 5000, false);
                assert_eq!(prr.credit(), expected);
                assert_eq!(prr.delivered, 3000);
                assert_eq!(prr.out, 0);
            }
            prr.sent(1000);
            // Reflect the successful retransmission in pipe. The proportional
            // bound is retained on zero delivery in either RFC9937 branch.
            prr.acknowledge(0, pipe + 1000, 5000, false);
            assert_eq!(prr.credit(), if pipe > 5000 { 500 } else { 1000 });
            assert_eq!(prr.delivered, 3000);
            assert_eq!(prr.out, 1000);
        }
    }

    #[test]
    fn prr_crb_equation_vectors_in_bytes() {
        // Non-half thresholds, CEIL rounding, branch equality, banked delivery,
        // partial-byte ACKs, overconsumption saturation and widened multiplication.
        for (flight, threshold, pipe, delivered, out, expected) in [
            (10_000, 7000, 8000, 1001, 0, 701),
            (10_000, 7000, 8000, 1001, 700, 1),
            (10_000, 7000, 7000, 1001, 0, 0),
            (10_000, 7000, 6999, 1001, 0, 1),
            (10_000, 7000, 3000, 3000, 1000, 2000),
            (10_000, 7000, 6998, 3000, 1000, 2),
            (10_000, 7000, 8000, 1, 0, 1),
            (10_000, 7000, 8000, 1, 2, 0),
            (10_000, 7000, 1000, 1, 2, 0),
            (10_000, 7000, 8000, 10_000, 0, 7000),
            (u32::MAX, u32::MAX - 1, u32::MAX, u32::MAX, 0, u32::MAX - 1),
        ] {
            let mut prr = Prr::new(flight, 1000, PrrAlgorithm::LegacyInitialCredit);
            prr.sent(out);
            prr.acknowledge(delivered, pipe, threshold, false);
            assert_eq!(prr.credit(), expected);
            assert_eq!(prr.delivered, u64::from(delivered));
            assert_eq!(prr.out, u64::from(out));
            prr.sent(expected);
            assert_eq!(prr.credit(), 0);
            assert_eq!(prr.out, u64::from(out) + u64::from(expected));
        }
    }

    #[test]
    fn legacy_prr_initial_state_and_guarantee_are_not_delivery() {
        let mut prr = Prr::new(10_000, 1000, PrrAlgorithm::LegacyInitialCredit);
        assert_eq!((prr.recover_fs, prr.delivered, prr.out), (10_000, 0, 0));
        assert_eq!(prr.credit(), 1000); // Characterize policy, not a CRB waiver.
        prr.acknowledge(0, 3000, 5000, false);
        assert_eq!(prr.credit(), 0);
        prr.guarantee_initial(1000);
        assert_eq!((prr.delivered, prr.out, prr.credit()), (0, 0, 1000));
        prr.sent(1000);
        assert_eq!((prr.delivered, prr.out, prr.credit()), (0, 1000, 0));
        assert!(prr.out > prr.delivered); // Strict conservation is not established.
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= type=test
    //= reason=Checks additional reductions at fixed cumulative flight, including prior ECN.
    //# In the absence of PRR [RFC6937], when RACK-TLP detects a lost
    //# retransmission, the congestion control MUST trigger an additional
    //# congestion response per the aforementioned principle in [RFC5681].
    fn rack_retransmission_loss_reduces_again_at_fixed_cumulative_flight() {
        for ecn in [false, true] {
            let mut c = Congestion::new(
                1000,
                RecoveryAlgorithm::NewReno,
                InitialWindow::Iw10,
                Seq(u32::MAX),
            );
            if ecn {
                assert!(c.on_ecn(Seq(1), 16_000, Seq(16_001)));
            }
            assert!(c.on_sack_recovery(Seq(1), 16_000, Seq(16_001)));
            assert_eq!(c.ssthresh(), 8000);
            c.retransmission_lost(16_000);
            assert_eq!((c.cwnd(), c.ssthresh()), (4000, 4000));
            c.retransmission_lost(16_000);
            assert_eq!((c.cwnd(), c.ssthresh()), (2000, 2000));
            assert_eq!(c.recover, Some(Seq(16_001)));
            assert_eq!(c.ecn_end, None);
        }
        let mut c = Congestion::new(
            1000,
            RecoveryAlgorithm::NewReno,
            InitialWindow::Iw10,
            Seq(u32::MAX),
        );
        assert!(c.on_ecn(Seq(1), 16_000, Seq(16_001)));
        assert_eq!((c.cwnd(), c.ssthresh()), (5000, 8000));
        c.retransmission_lost(16_000);
        assert_eq!((c.cwnd(), c.ssthresh()), (2500, 2500));
    }

    #[test]
    // Partial test: estimator vectors and capped backoff; does not test Karn sample
    // exclusion or timer lifecycle.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
    //= type=test
    //# The RTO MUST be computed according to the algorithm in [10], including Karn's
    //# algorithm for taking RTT samples (MUST-18).
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# (2.1) Until a round-trip time (RTT) measurement has been made for a segment sent
    //# between the sender and receiver, the sender SHOULD set RTO <- 1 second, though the
    //# "backing off" on repeated retransmission discussed in (5.5) still applies.
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# (2.2) When the first RTT measurement R is made, the host MUST set
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# (2.3) When a subsequent RTT measurement R' is made, a host MUST set
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# That is, updating RTTVAR and SRTT MUST be computed in the above order.
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# The above SHOULD be computed using alpha=1/8 and beta=1/4 (as suggested in [JK88]).
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# After the computation, a host MUST update RTO <- SRTT + max (G, K*RTTVAR)
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# (2.5) A maximum value MAY be placed on RTO provided it is at least 60 seconds.
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# To compute the current RTO, a TCP sender maintains two state variables, SRTT (smoothed
    //# round-trip time) and RTTVAR (round-trip time variation). In addition, we assume a
    //# clock granularity of G seconds.
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# SRTT <- R RTTVAR <- R/2 RTO <- SRTT + max (G, K*RTTVAR) where K = 4.
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'| SRTT <- (1 - alpha) * SRTT + alpha
    //# * R'
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# The value of SRTT used in the update to RTTVAR is its value before updating SRTT
    //# itself using the second assignment.
    // Estimator vectors, not connection sampling or timers.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-5
    //= type=test
    //= reason=Estimator vectors, not connection sampling or timers.
    //# Note that after retransmitting, once a new RTT measurement is obtained (which can only
    //# happen when new data has been sent and acknowledged), the computations outlined in
    //# Section 2 are performed, including the computation of RTO, which may result in
    //# "collapsing" RTO back down after it has been subject to exponential back off (rule
    //# 5.5).
    fn rtt_vectors_and_backoff() {
        let mut rtt = RttEstimator::new(MIN_RTO);
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
    // Default one-second minimum and estimator granularity.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Default one-second minimum and estimator granularity.
    //# After the computation, a host MUST update RTO <- SRTT + max (G, K*RTTVAR)
    // Default one-second minimum and estimator granularity are implemented; explicit subsecond compatibility is separately scoped, not universal floor compliance.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Default one-second minimum and estimator granularity are implemented; explicit subsecond compatibility is separately scoped, not universal floor compliance.
    //# (2.4) Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be
    //# rounded up to 1 second.
    // Default one-second minimum and estimator granularity.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-4
    //= type=test
    //= reason=Default one-second minimum and estimator granularity.
    //# However, if the K*RTTVAR term in the RTO calculation equals zero, the variance term
    //# MUST be rounded to G seconds (i.e., use the equation given in step 2.3).
    // Default one-second minimum and estimator granularity.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Default one-second minimum and estimator granularity.
    //# To compute the current RTO, a TCP sender maintains two state variables, SRTT (smoothed
    //# round-trip time) and RTTVAR (round-trip time variation). In addition, we assume a
    //# clock granularity of G seconds.
    fn rtt_floor_granularity_and_extremes() {
        let mut rtt = RttEstimator::new(MIN_RTO);
        rtt.sample(0);
        assert_eq!(rtt.rto(), MIN_RTO);
        rtt.sample(1);
        assert_eq!(rtt.rto(), MIN_RTO);
        let mut rtt = RttEstimator::new(MIN_RTO);
        for _ in 0..100 {
            rtt.sample(2_000_000);
        }
        assert_eq!(rtt.rto(), 2_001_000);
        let mut rtt = RttEstimator::new(MIN_RTO);
        rtt.sample(u64::MAX);
        rtt.sample(u64::MAX);
        assert_eq!(rtt.srtt, Some(u64::MAX));
        assert_eq!(rtt.rto(), MAX_RTO);
        rtt.sample(0);
        assert_eq!(rtt.srtt, Some((7 * u64::MAX as u128 / 8) as u64));
        assert_eq!(rtt.rto(), MAX_RTO);
    }

    #[test]
    // Explicit configurable floor includes subsecond deviation, not universal RFC floor compliance.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Explicit configurable floor includes subsecond deviation, not universal RFC floor compliance.
    //# (2.1) Until a round-trip time (RTT) measurement has been made for a segment sent
    //# between the sender and receiver, the sender SHOULD set RTO <- 1 second, though the
    //# "backing off" on repeated retransmission discussed in (5.5) still applies.
    // Approved user-selected Linux-compatible subsecond SHOULD departure; assertions preserve initial1s, sampled floor, exact doubling and60s cap, not universal RFC floor compliance.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Approved user-selected Linux-compatible subsecond SHOULD departure; assertions preserve initial1s, sampled floor, exact doubling and60s cap, not universal RFC floor compliance.
    //# (2.4) Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be
    //# rounded up to 1 second.
    // Explicit configurable floor includes subsecond deviation, not universal RFC floor compliance.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-2
    //= type=test
    //= reason=Explicit configurable floor includes subsecond deviation, not universal RFC floor compliance.
    //# (2.5) A maximum value MAY be placed on RTO provided it is at least 60 seconds.
    // Explicit configurable floor includes subsecond deviation, not universal RFC floor compliance.
    //= https://www.rfc-editor.org/rfc/rfc6298#section-4
    //= type=test
    //= reason=Explicit configurable floor includes subsecond deviation, not universal RFC floor compliance.
    //# However, if the K*RTTVAR term in the RTO calculation equals zero, the variance term
    //# MUST be rounded to G seconds (i.e., use the equation given in step 2.3).
    fn configurable_rto_floor_keeps_initial_and_backoff_bounds() {
        for minimum in [1, 200_000, 1_000_000, MAX_RTO] {
            let mut rtt = RttEstimator::new(minimum);
            assert_eq!(rtt.rto(), 1_000_000);
            rtt.backoff();
            assert_eq!(rtt.rto(), 2_000_000);
            rtt.sample(100_000);
            assert_eq!(rtt.rto(), 300_000u64.max(minimum));
            rtt.backoff();
            assert_eq!(rtt.rto(), (300_000u64.max(minimum) * 2).min(MAX_RTO));
            for _ in 0..100 {
                rtt.backoff();
            }
            assert_eq!(rtt.rto(), MAX_RTO);
            for _ in 0..100 {
                rtt.sample(1);
            }
            assert_eq!(rtt.rto(), minimum.max(1001));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc8985#section-7.4.2
    //= type=test
    //= reason=Asserts sharing original-flight reduction and a separate reduction for a later flight.
    //# The sender then
    //# SHOULD invoke a congestion control response equivalent to a fast
    //# recovery.
    fn tlp_reduction_epoch_shares_reduction_but_does_not_guard_recovery_entry() {
        for ecn in [false, true] {
            let mut c = Congestion::new(
                1000,
                RecoveryAlgorithm::NewReno,
                InitialWindow::Iw10,
                Seq(u32::MAX),
            );
            if ecn {
                assert!(c.on_ecn(Seq(1), 10_000, Seq(10_001)));
            }
            assert!(c.on_tlp_repair(Seq(5001), 10_000, Seq(10_001)));
            assert_eq!(c.ssthresh(), 5000);
            assert_eq!(c.recover, None);
            assert_eq!(c.tlp_reduction_end, Some(Seq(10_001)));
            assert!(!c.in_recovery());
            assert!(!c.on_tlp_repair(Seq(5001), 5000, Seq(10_001)));
            assert!(!c.on_ecn(Seq(5001), 5000, Seq(10_001)));
            assert!(c.on_sack_recovery(Seq(5001), 5000, Seq(10_001)));
            assert_eq!(c.ssthresh(), 5000);
            assert!(c.in_recovery());
            assert!(!c.on_ack(Seq(10_001), 5000, 0));
            assert!(!c.in_recovery());
            assert!(!c.on_ack(Seq(10_002), 1, 0));
            assert_eq!(c.tlp_reduction_end, None);
            assert!(c.on_sack_recovery(Seq(10_002), 4000, Seq(14_002)));
            assert_eq!(c.ssthresh(), 2000); // A genuinely later flight reduces again.
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //# IW, the initial value of cwnd, MUST be set using the following guidelines as an upper bound.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //# If SMSS > 2190 bytes: IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
    //# If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes): IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
    //# if SMSS <= 1095 bytes: IW = 4 * SMSS bytes and MUST NOT be more than 4 segments
    fn default_initial_window_piecewise_boundaries() {
        for (mss, expected) in [
            (1, 4),
            (1_095, 4_380),
            (1_096, 3_288),
            (1_448, 4_344),
            (2_190, 6_570),
            (2_191, 4_382),
            (u32::MAX, MAX_WINDOW),
        ] {
            for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
                let c = Congestion::new(mss, algorithm, InitialWindow::Rfc5681, Seq(u32::MAX));
                assert_eq!(c.cwnd(), expected);
                assert_eq!(c.initial_window(), expected);
            }
        }
    }

    #[test]
    fn tlp_loss_response_shares_ecn_and_recovery_epoch_guards() {
        let mut c = Congestion::new(
            1000,
            RecoveryAlgorithm::NewReno,
            InitialWindow::Iw10,
            Seq(u32::MAX),
        );
        assert!(c.on_ecn(Seq(1), 8000, Seq(8001)));
        assert_eq!(c.ssthresh(), 4000);
        assert!(c.on_sack_recovery(Seq(7001), 2000, Seq(8001)));
        assert_eq!(c.ssthresh(), 4000); // do not halve again inside ECN epoch
        assert!(!c.on_sack_recovery(Seq(7001), 2000, Seq(8001)));
        c.cancel_sack_recovery();
        assert!(!c.on_sack_recovery(Seq(7001), 2000, Seq(8001)));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= type=test
    //= reason=Selected IW10 restart choice uses min(current cwnd, IW10); helper covers grown and reduced cwnd and changing MSS, and wire idle trace asserts burst limited to ten MSS. iw10_transmit_idle_restart_and_data_rto covers the last-data idle trigger despite received requests and emitted pure ACKs; this evidence is the optional window value only.
    //# Optionally, a TCP MAY set the restart window to the minimum of the value used for the
    //# initial window and the current value of cwnd (in other words, using a larger value for
    //# the restart window should never increase the size of cwnd).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.1
    //= type=test
    //= reason=restart_after_idle sets min(cwnd,selected IW), never increases a reduced cwnd; both algorithm choices assert reduced and grown values. iw10_transmit_idle_restart_and_data_rto covers the last-data idle trigger; default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss cover default IW calculation.
    //# For the purposes of this standard, we define RW = min(IW,cwnd).
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= type=test
    //= reason=Explicit InitialWindow::Iw10 computes min(10*MSS,max(2*MSS,14600)) with conservative integer cap. Tests assert representative small/normal/jumbo/overflow vectors, negotiated MSS/path/options and initial handshake value. Default RFC5681 arithmetic is covered separately by default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss.
    //# min (10*MSS, max (2*MSS, 14600)) (1)
    //= https://www.rfc-editor.org/rfc/rfc6928#section-2
    //= type=test
    //= reason=IW10 loss window remains one effective MSS; helper and wire trace assert timeout reduction, one retransmit and denied next output.
    //# These changes do NOT change the loss window, which must remain 1 segment of MSS bytes
    //# (to permit the lowest possible window size in the case of severe congestion).
    fn iw10_bounds_mss_changes_timeout_and_idle_restart() {
        for (mss, window) in [
            (1_000, 10_000),
            (1_460, 14_600),
            (3_000, 14_600),
            (8_000, 16_000),
            (u32::MAX, MAX_WINDOW),
        ] {
            for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
                let mut c = Congestion::new(mss, algorithm, InitialWindow::Iw10, Seq(u32::MAX));
                assert_eq!(c.cwnd(), window);
                c.on_ack(Seq(1), 1, 0);
                c.restart_after_idle();
                assert_eq!(c.cwnd(), window);
                c.on_timeout(window, Seq(2));
                assert_eq!(c.cwnd(), mss.min(MAX_WINDOW));
                c.restart_after_idle();
                assert_eq!(c.cwnd(), mss.min(MAX_WINDOW));
            }
        }
        let mut c = Congestion::new(
            3_000,
            RecoveryAlgorithm::default(),
            InitialWindow::Iw10,
            Seq(u32::MAX),
        );
        c.set_initial_mss(1_000, false);
        assert_eq!(c.cwnd(), 10_000);
        c.set_mss(500);
        assert_eq!(c.cwnd(), 5_000);
        c.set_mss(1_000);
        assert_eq!(c.cwnd(), 5_000);
        c.restart_after_idle();
        assert_eq!(c.cwnd(), 5_000);
        c.on_timeout(5_000, Seq(100));
        c.set_initial_mss(500, true);
        assert_eq!(c.cwnd(), 500);
    }

    #[test]
    // Partial test: initial window, ACK-driven growth, timeout reduction, and congestion-
    // avoidance byte counting; not end-to-end congestion-control conformance.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //= type=test
    //# A TCP endpoint MUST implement the basic congestion control algorithms slow start,
    //# congestion avoidance, and exponential backoff of RTO to avoid creating congestion
    //# collapse conditions (MUST-19).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# * MAY increment cwnd by SMSS bytes
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# The RECOMMENDED way to increase cwnd during congestion avoidance is to count the number
    //# of bytes that have been acknowledged by ACKs for new data.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Both Reno/NewReno and default/IW10 retain a one-effective-MSS loss window. Helper verifies cwnd reset and ACK-driven transition; IW10 wire test asserts exactly one retransmission and no second output.
    //# Furthermore, upon a timeout (as specified in [RFC2988]) cwnd MUST be set to no more than
    //# the loss window, LW, which equals 1 full-sized segment (regardless of the value of IW).
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# The slow start algorithm is used when cwnd < ssthresh, while the congestion avoidance
    //# algorithm is used when cwnd > ssthresh. When cwnd and ssthresh are equal, the sender may
    //# use either slow start or congestion avoidance.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# During slow start, a TCP increments cwnd by at most SMSS bytes for each ACK received
    //# that cumulatively acknowledges new data. Slow start ends when cwnd exceeds ssthresh (or,
    //# optionally, when it reaches it, as noted above) or when congestion is observed. While
    //# traditionally TCP implementations have increased cwnd by precisely SMSS bytes upon
    //# receipt of an ACK covering new data, we RECOMMEND that TCP implementations increase
    //# cwnd, per:
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# cwnd += min (N, SMSS) (2)
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# We note that [RFC3465] allows for cwnd increases of more than SMSS bytes for incoming
    //# acknowledgments during slow start on an experimental basis; however, such behavior is
    //# not allowed as part of the standard.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-5
    //= type=test
    //= reason=Shared Reno/NewReno slow start and byte-counting congestion avoidance; applies outside fast/SACK recovery. Helper vectors assert min(acked,SMSS), zero-ACK no growth, threshold equality chooses avoidance, and 4000 one-byte ACKs produce exactly one MSS increase; not a wall-clock RTT/output proof.
    //# In response to the ACK division attack outlined in [SCWA99], this document RECOMMENDS
    //# increasing the congestion window based on the number of bytes newly acknowledged in each
    //# arriving ACK rather than by a particular constant on each arriving ACK (as outlined in
    //# section 3.1).
    fn initial_slow_start_and_byte_counting() {
        for (mss, window) in [(500, 2_000), (1_000, 4_000), (1_460, 4_380), (3_000, 6_000)] {
            assert_eq!(
                Congestion::new(
                    mss,
                    RecoveryAlgorithm::default(),
                    InitialWindow::default(),
                    Seq(u32::MAX)
                )
                .cwnd(),
                window
            );
        }
        let mut c = Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
            Seq(u32::MAX),
        );
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
        assert!(!c.on_duplicate_ack(Seq(1), flight, end, false));
        assert!(!c.on_duplicate_ack(Seq(1), flight, end, false));
        c.on_duplicate_ack(Seq(1), flight, end, false)
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= type=test
    //= reason=Enhanced SACK recovery target halves eligible flight with two-MSS floor; sack_entry_partial_and_full_ack asserts 8000 -> 4000 and minimum case. Negotiated SACK/non-RACK and RACK lost-retransmission responses separately tested; ECN shared epoch is distinct policy.
    //# That is, when the first loss in a window of data is detected, ssthresh MUST be set to no
    //# more than the value given by equation (4).
    fn sack_entry_partial_and_full_ack() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(0), Seq(u32::MAX - 3_999)] {
                for extra in [0, 1] {
                    let end = base.wrapping_add(8_000);
                    let mut c =
                        Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
                    c.acknowledged = 3_000;
                    assert!(c.on_sack_recovery(base, 8_000, end));
                    assert_eq!((c.cwnd(), c.ssthresh()), (4_000, 4_000));
                    assert!(c.sack_recovery);
                    assert!(!c.fast_recovery);
                    assert_eq!(c.acknowledged, 0);
                    assert!(!c.on_sack_recovery(end, 2_000, end.wrapping_add(4_000)));
                    assert!(!three_duplicates(&mut c, 8_000, end));
                    assert!(!c.on_ack(base, 0, 8_000));
                    assert!(!c.on_ack(end.wrapping_add(1 << 31), 1, 8_000));
                    assert!(c.sack_recovery);
                    assert!(!c.on_ack(base.wrapping_add(2_000), 2_000, 6_000));
                    assert!(!c.on_ack_with_ecn(base.wrapping_add(3_000), 1_000, 5_000, true));
                    assert_eq!(c.cwnd(), 4_000);
                    assert_eq!(c.acknowledged, 0);
                    assert!(c.sack_recovery);
                    assert!(!c.on_ack_with_ecn(end.wrapping_add(extra), 5_000 + extra, 0, true));
                    assert!(!c.sack_recovery);
                    assert_eq!(c.cwnd(), 2_000);
                    assert_eq!(c.recover, if extra == 0 { Some(end) } else { None });
                    assert!(c.on_sack_recovery(
                        end.wrapping_add(extra),
                        1_000,
                        end.wrapping_add(4_000)
                    ));
                    assert_eq!((c.cwnd(), c.ssthresh()), (2_000, 2_000));
                }
            }
        }
        let mut c = Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
            Seq(u32::MAX),
        );
        assert!(three_duplicates(&mut c, 8_000, Seq(8_000)));
        assert!(!c.on_sack_recovery(Seq(8_000), 2_000, Seq(12_000)));
        assert!(c.fast_recovery);
        assert!(!c.sack_recovery);
        assert_eq!(c.cwnd(), 7_000);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=on_timeout halves supplied FlightSize with two-MSS floor on first timeout; repeated same-segment timeout keeps threshold. Helper asserts 10000 flight -> 5000 threshold, repeat at flight=2000 -> unchanged 5000; minimum floor separately asserted by sack_timeout_boundary_and_cancel_preserve_epoch. ECN sharing is a separate RFC3168 policy.
    //# When a TCP sender detects segment loss using the retransmission timer and the given
    //# segment has not yet been resent by way of the retransmission timer, the value of
    //# ssthresh MUST be set to no more than the value given in equation (4):
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Threshold helper uses actual eligible flight /2 with two-MSS minimum; timeout vectors assert 10000->5000 and SACK boundary vectors assert floor. Limited Transmit exclusion is caller-owned and separately evidenced.
    //# ssthresh = max (FlightSize / 2, 2*SMSS) (4)
    fn sack_timeout_boundary_and_cancel_preserve_epoch() {
        for end in [Seq(10_000), Seq(0), Seq(u32::MAX)] {
            let mut c = Congestion::new(
                1_000,
                RecoveryAlgorithm::default(),
                InitialWindow::default(),
                Seq(u32::MAX),
            );
            assert!(c.on_sack_recovery(end.wrapping_add(u32::MAX - 7_999), 8_000, end));
            c.on_timeout(8_000, end);
            assert!(!c.sack_recovery);
            assert!(!c.fast_recovery);
            assert_eq!((c.cwnd(), c.ssthresh()), (1_000, 4_000));
            for ack in [end.wrapping_add(u32::MAX), end.wrapping_add(1 << 31)] {
                assert!(!c.on_sack_recovery(ack, 4_000, end.wrapping_add(4_000)));
                assert_eq!(c.cwnd(), 1_000);
                assert_eq!(c.recover, Some(end));
            }
            assert!(c.on_sack_recovery(end, 4_000, end.wrapping_add(4_000)));
            assert_eq!(c.cwnd(), 2_000);
            c.on_retransmit(end.wrapping_add(1_000));
            let retransmitted_end = c.retransmitted_end;
            let recover = c.recover;
            let timeout_retransmitted = c.timeout_retransmitted;
            c.cancel_sack_recovery();
            c.cancel_sack_recovery();
            assert!(!c.sack_recovery);
            assert!(!c.fast_recovery);
            assert_eq!((c.cwnd(), c.ssthresh()), (2_000, 2_000));
            assert_eq!(c.recover, recover);
            assert_eq!(c.retransmitted_end, retransmitted_end);
            assert_eq!(c.timeout_retransmitted, timeout_retransmitted);
            assert!(!three_duplicates(&mut c, 4_000, end.wrapping_add(4_000)));
            assert_eq!(c.cwnd(), 2_000);
            assert!(!c.on_ecn(end, 4_000, end.wrapping_add(4_000)));
        }
    }

    #[test]
    fn sack_ecn_epoch_shares_only_current_reduction() {
        for base in [Seq(0), Seq(u32::MAX - 3_999)] {
            let end = base.wrapping_add(16_000);
            for extra in [0, 1] {
                let mut c = Congestion::new(
                    1_000,
                    RecoveryAlgorithm::default(),
                    InitialWindow::default(),
                    Seq(u32::MAX),
                );
                assert!(c.on_ecn(base, 16_000, end));
                assert!(c.on_sack_recovery(
                    end.wrapping_add(extra),
                    4_000,
                    end.wrapping_add(4_000)
                ));
                let threshold = if extra == 0 { 8_000 } else { 2_000 };
                assert_eq!((c.cwnd(), c.ssthresh()), (threshold, threshold));
            }
            let mut c = Congestion::new(
                1_000,
                RecoveryAlgorithm::default(),
                InitialWindow::default(),
                Seq(u32::MAX),
            );
            assert!(c.on_ecn(base, 16_000, end));
            assert!(c.on_sack_recovery(base, 4_000, end));
            assert_eq!((c.cwnd(), c.ssthresh()), (8_000, 8_000));
            assert!(!c.on_ecn(base, 4_000, end));
            c.cancel_sack_recovery();
            assert_eq!(c.ecn_end, Some(end));
            assert!(!c.on_ecn(end, 4_000, end));
        }
    }

    #[test]
    fn sack_arbitrary_retransmissions_keep_rto_accounting() {
        for base in [Seq(0), Seq(u32::MAX - 3_999)] {
            for acked in [2_000, 3_000] {
                let end = base.wrapping_add(16_000);
                let mut c = Congestion::new(
                    1_000,
                    RecoveryAlgorithm::default(),
                    InitialWindow::default(),
                    Seq(u32::MAX),
                );
                assert!(c.on_ecn(base, 16_000, end));
                assert!(c.on_sack_recovery(base, 16_000, end));
                c.on_retransmit(base.wrapping_add(3_000));
                c.on_retransmit(base.wrapping_add(1_000));
                assert_eq!(c.retransmitted_end, Some(base.wrapping_add(3_000)));
                c.timeout_retransmitted = true;
                assert!(!c.on_ack_with_ecn(base.wrapping_add(acked), acked, 16_000 - acked, true));
                assert!(!c.timeout_retransmitted);
                assert_eq!(c.retransmitted_end.is_some(), acked < 3_000);
                assert_eq!(c.cwnd(), 8_000);
                c.on_timeout(16_000 - acked, end);
                assert_eq!(c.ssthresh(), if acked < 3_000 { 4_000 } else { 8_000 });
                assert!(!c.sack_recovery);
                assert_eq!(c.cwnd(), 1_000);
            }
        }
    }

    #[test]
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# When in fast recovery, this variable records the send sequence number that must be
    //# acknowledged before the fast recovery procedure is declared to be over.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
    //= type=test
    //= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
    //# The NewReno modification applies to the fast recovery procedure that begins when three
    //# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
    //# ACK arrives that acknowledges all of the data up to and including the data that was
    //# outstanding when the fast recovery procedure began.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //# The procedures specified in Section 3.2 of [RFC5681] are followed, with the
    //# modifications listed below.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //# When the third duplicate ACK is received, the TCP sender first checks the value of
    //# recover to see if the Cumulative Acknowledgment field covers more than recover. If so,
    //# the value of recover is incremented to the value of the highest sequence number
    //# transmitted by the TCP so far. The TCP then enters fast retransmit (step 2 of Section
    //# 3.2 of [RFC5681]). If not, the TCP does not enter fast retransmit and does not reset
    //# ssthresh.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# If this ACK acknowledges all of the data up to and including recover, then the ACK
    //# acknowledges all the intermediate segments sent between the original transmission of
    //# the lost segment and the receipt of the third duplicate ACK. Set cwnd to either (1)
    //# min (ssthresh, max(FlightSize, SMSS) + SMSS) or (2) ssthresh, where ssthresh is the
    //# value set when fast retransmit was entered, and where FlightSize in (1) is the amount
    //# of data presently outstanding.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# Exit the fast recovery procedure.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# If this ACK does *not* acknowledge all of the data up to and including recover, then
    //# this is a partial ACK.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=NewReno partial ACK schedules retx_pending; committed output starts at snd_una. newreno_partial_ack_wire_timer_and_exit_boundaries asserts each missing sequence/payload, continued recovery and failed-output rollback, including wrap.
    //# In this case, retransmit the first unacknowledged segment.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //# Deflate the congestion window by the amount of new data acknowledged by the Cumulative
    //# Acknowledgment field. If the partial ACK acknowledges at least one SMSS of new data,
    //# then add back SMSS bytes to the congestion window.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# Do not exit the fast recovery procedure (i.e., if any duplicate ACKs subsequently
    //# arrive, execute step 4 of Section 3.2 of [RFC5681]).
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //# Because the acknowledgment field contains the sequence number that the sender next
    //# expects to receive, the acknowledgment "ack_number" covers more than recover when
    //# ack_number - 1 > recover; i.e., at least one byte more of data is acknowledged beyond
    //# the highest byte that was outstanding when fast retransmit was last entered.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# This document also does not address issues of adjusting the duplicate acknowledgment
    //# threshold, but assumes the threshold specified in the IETF standards; the current
    //# standard is [RFC5681], which specifies a threshold of three duplicate acknowledgments.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Selected full-ACK option1 cwnd=min(ssthresh,max(FlightSize,SMSS)+SMSS). Lost-duplicate-ACK wire trace newreno_partial_ack_wire_timer_and_exit_boundaries polls to exhaustion: two fresh MSS at zero flight, one at residual one-MSS flight.
    //# In Section 3.2, step 3 above, it is noted that implementations should take measures to
    //# avoid a possible burst of data when leaving fast recovery, in case the amount of new
    //# data that the sender is eligible to send due to the new value of the congestion window
    //# is large.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# An implementation may want to use a separate flag to record whether or not it is
    //# presently in the fast recovery procedure.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# The use of the value of the duplicate acknowledgment counter for this purpose is not
    //# reliable, because it can be reset upon window updates and out-of- order
    //# acknowledgments.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Controller assertions only, not wire retransmission or timer management.
    //# Entry into fast recovery is only possible when the Cumulative Acknowledgment field
    //# covers more than the state variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Controller assertions only, not wire retransmission or timer management.
    //# Note that after cwnd is set based on the procedure for exiting fast recovery (Section
    //# 3.2, step 3), cwnd should not be updated until a further event occurs (e.g., arrival
    //# of an ack, or timeout) after this adjustment.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= type=test
    //= reason=Non-ECE non-SACK Reno/NewReno fast entry: helper asserts cwnd=ssthresh+3SMSS (7000=4000+3000); wire test asserts SND.UNA retransmission. Negotiated SACK/RACK/PRR instead follow section4.3 modified recovery and do not use Reno inflation.
    //# The lost segment starting at SND.UNA MUST be retransmitted and cwnd set to ssthresh plus
    //# 3*SMSS.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= type=test
    //= reason=Non-ECE non-SACK fast recovery only: helper fourth DupACK raises 7000 to 8000 at MSS1000; accepted ECE instead follows RFC3168 no-growth policy. Negotiated SACK/RACK/PRR do not artificially inflate cwnd; see section4.3 obligations.
    //# For each additional duplicate ACK received (after the third), cwnd MUST be incremented
    //# by SMSS.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.3
    //= type=test
    //= reason=Recommendation to employ multi-loss recovery: default NewReno handles partial ACKs; opt-in negotiated SACK repairs multiple holes. These tests evidence algorithm selection and multi-loss repair only, not every section4.3 general bound (TODOs remain).
    //# We RECOMMEND that TCP implementors employ some form of advanced loss recovery that can
    //# cope with multiple losses in a window of data. The algorithms detailed in [RFC3782] and
    //# [RFC3517] conform to the general principles outlined above. We note that while these are
    //# not the only two algorithms that conform to the above general principles these two
    //# algorithms have been vetted by the community and are currently on the Standards Track.
    fn newreno_partial_and_full_ack() {
        let mut c = Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
            Seq(u32::MAX),
        );
        assert!(three_duplicates(&mut c, 8_000, Seq(8_000)));
        assert_eq!((c.ssthresh(), c.cwnd()), (4_000, 7_000));
        assert!(!c.on_duplicate_ack(Seq(1), 8_000, Seq(8_000), false));
        assert_eq!(c.cwnd(), 8_000);
        assert!(c.on_ack(Seq(2_000), 2_000, 6_000));
        assert_eq!(c.cwnd(), 7_000);
        assert!(c.on_ack(Seq(2_500), 500, 5_500));
        assert_eq!(c.cwnd(), 6_500);
        assert!(!c.on_duplicate_ack(Seq(1), 5_500, Seq(8_000), false));
        assert_eq!(c.cwnd(), 7_500);
        assert!(!c.on_ack(Seq(8_000), 5_500, 0));
        assert_eq!(c.cwnd(), 2_000);
        assert!(!c.fast_recovery);
        assert!(!three_duplicates(&mut c, 4_000, Seq(12_000)));
        c.on_ack(Seq(8_001), 1, 3_999);
        assert!(three_duplicates(&mut c, 3_999, Seq(12_000)));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= type=test
    //# When the next ACK arrives that acknowledges previously
    //# unacknowledged data, a TCP MUST set cwnd to ssthresh (the value
    //# set in step 2).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
    //= type=test
    //= reason=Checks selectable recovery exit and partial-ACK behavior, wraparound and conservative epoch guards; not comprehensive external-RFC verification.
    //# An endpoint MAY implement such alternative
    //# algorithms provided that the algorithms are conformant with the TCP
    //# specifications from the IETF Standards Track as described in RFC
    //# 2914, RFC 5033 [7], and RFC 8961 [15] (MAY-18).
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-1
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Both algorithms and sequence wrap tested separately.
    //# This document applies to TCP connections that are unable to use the TCP Selective
    //# Acknowledgment (SACK) option, either because the option is not locally supported or
    //# because the TCP peer did not indicate a willingness to use SACK.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //# When in fast recovery, this variable records the send sequence number that must be
    //# acknowledged before the fast recovery procedure is declared to be over.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //# If this ACK acknowledges all of the data up to and including recover, then the ACK
    //# acknowledges all the intermediate segments sent between the original transmission of
    //# the lost segment and the receipt of the third duplicate ACK. Set cwnd to either (1)
    //# min (ssthresh, max(FlightSize, SMSS) + SMSS) or (2) ssthresh, where ssthresh is the
    //# value set when fast retransmit was entered, and where FlightSize in (1) is the amount
    //# of data presently outstanding.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //# Exit the fast recovery procedure.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //# If this ACK does *not* acknowledge all of the data up to and including recover, then
    //# this is a partial ACK.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=NewReno partial ACK schedules retx_pending; committed output starts at snd_una. newreno_partial_ack_wire_timer_and_exit_boundaries asserts each missing sequence/payload, continued recovery and failed-output rollback, including wrap.
    //# In this case, retransmit the first unacknowledged segment.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Both algorithms and sequence wrap tested separately.
    //# Deflate the congestion window by the amount of new data acknowledged by the Cumulative
    //# Acknowledgment field. If the partial ACK acknowledges at least one SMSS of new data,
    //# then add back SMSS bytes to the congestion window.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //# Do not exit the fast recovery procedure (i.e., if any duplicate ACKs subsequently
    //# arrive, execute step 4 of Section 3.2 of [RFC5681]).
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Selected full-ACK option1 cwnd=min(ssthresh,max(FlightSize,SMSS)+SMSS). Lost-duplicate-ACK wire trace newreno_partial_ack_wire_timer_and_exit_boundaries polls to exhaustion: two fresh MSS at zero flight, one at residual one-MSS flight.
    //# In Section 3.2, step 3 above, it is noted that implementations should take measures to
    //# avoid a possible burst of data when leaving fast recovery, in case the amount of new
    //# data that the sender is eligible to send due to the new value of the congestion window
    //# is large.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Both algorithms and sequence wrap tested separately.
    //# When updating the Cumulative Acknowledgment field outside of fast recovery, the state
    //# variable recover may also need to be updated in order to continue to permit possible
    //# entry into fast recovery (Section 3.2, step 2). This issue arises when an update of
    //# the Cumulative Acknowledgment field results in a sequence wraparound that affects the
    //# ordering between the Cumulative Acknowledgment field and the state variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Both algorithms and sequence wrap tested separately.
    //# Note that after cwnd is set based on the procedure for exiting fast recovery (Section
    //# 3.2, step 3), cwnd should not be updated until a further event occurs (e.g., arrival
    //# of an ack, or timeout) after this adjustment.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
    //= type=test
    //= reason=RecoveryAlgorithm::Reno only, without negotiated SACK: on first advancing ACK sets cwnd=ssthresh; reno_and_newreno_recovery_exit explicitly asserts 4000 for partial and full Reno ACKs. NewReno/SACK/RACK/PRR use enhanced section4.3 recovery, not immediate Reno deflation.
    //# When the next ACK arrives that acknowledges previously unacknowledged data, a TCP MUST
    //# set cwnd to ssthresh (the value set in step 2).
    fn reno_and_newreno_recovery_exit() {
        assert_eq!(RecoveryAlgorithm::default(), RecoveryAlgorithm::NewReno);
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(0), Seq(u32::MAX - 3_999)] {
                for acked in [500, 2_000, 8_000, 9_000] {
                    let end = base.wrapping_add(8_000);
                    let mut c =
                        Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
                    assert!(three_duplicates(&mut c, 8_000, end));
                    // Control-only and ambiguous ACKs cannot exit recovery.
                    assert!(!c.on_ack(base, 0, 8_000));
                    assert!(!c.on_ack(end.wrapping_add(1 << 31), 1, 8_000));
                    assert!(c.fast_recovery);
                    let partial = acked < 8_000;
                    let stays = partial && algorithm == RecoveryAlgorithm::NewReno;
                    assert_eq!(
                        c.on_ack(
                            base.wrapping_add(acked),
                            acked,
                            8_000u32.saturating_sub(acked)
                        ),
                        stays
                    );
                    assert_eq!(c.fast_recovery, stays);
                    let expected = if algorithm == RecoveryAlgorithm::Reno {
                        4_000
                    } else if partial {
                        7_000 - acked + if acked >= 1_000 { 1_000 } else { 0 }
                    } else {
                        2_000
                    };
                    assert_eq!(c.cwnd(), expected);
                    assert_eq!(c.recover, if acked > 8_000 { None } else { Some(end) });
                    if algorithm == RecoveryAlgorithm::Reno && partial {
                        assert!(!three_duplicates(&mut c, 6_000, end));
                        assert_eq!(c.cwnd(), 4_000);
                        assert!(!c.on_ecn(end, 6_000, end));
                    }
                }
            }
        }
    }

    #[test]
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.1
    //= type=test
    //= reason=No-SACK NewReno wire entry, partial-ACK continuation, full-ACK exit and active-recovery RTO exit are asserted by newreno_partial_ack_wire_timer_and_exit_boundaries. timeout_marker_boundaries_and_wrap asserts timeout marker replacement; initial guard and strict admission are asserted by newreno_initial_boundary_and_loss_epoch_are_distinct.
    //# The NewReno modification applies to the fast recovery procedure that begins when three
    //# duplicate ACKs are received and ends when either a retransmission timeout occurs or an
    //# ACK arrives that acknowledges all of the data up to and including the data that was
    //# outstanding when the fast recovery procedure began.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# When the third duplicate ACK is received, the TCP sender first checks the value of
    //# recover to see if the Cumulative Acknowledgment field covers more than recover. If so,
    //# the value of recover is incremented to the value of the highest sequence number
    //# transmitted by the TCP so far. The TCP then enters fast retransmit (step 2 of Section
    //# 3.2 of [RFC5681]). If not, the TCP does not enter fast retransmit and does not reset
    //# ssthresh.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=on_timeout stores exclusive highest_sent and clears recovery; timeout_marker_boundaries_and_wrap directly asserts active flag clear and marker replacement. newreno_partial_ack_wire_timer_and_exit_boundaries asserts active wire RTO at exact expiry.
    //# After a retransmit timeout, record the highest sequence number transmitted in the
    //# variable recover, and exit the fast recovery procedure if applicable.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-3.2
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# Because the acknowledgment field contains the sequence number that the sender next
    //# expects to receive, the acknowledgment "ack_number" covers more than recover when
    //# ack_number - 1 > recover; i.e., at least one byte more of data is acknowledged beyond
    //# the highest byte that was outstanding when fast retransmit was last entered.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-4
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# After each retransmit timeout, the highest sequence number transmitted so far is
    //# recorded in the variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-4
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# For a TCP sender that implements the algorithm specified in Section 3.2 of this
    //# document, the sender does not infer a packet drop from duplicate acknowledgments in
    //# this scenario. As always, the retransmit timer is the backup mechanism for inferring
    //# packet loss in this case.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# Entry into fast recovery is only possible when the Cumulative Acknowledgment field
    //# covers more than the state variable recover.
    // No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=No-SACK NewReno only; initial guard, literal partial deflation, wire repair and RTO have dedicated assertions, not a global enhanced-recovery claim. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# When updating the Cumulative Acknowledgment field outside of fast recovery, the state
    //# variable recover may also need to be updated in order to continue to permit possible
    //# entry into fast recovery (Section 3.2, step 2). This issue arises when an update of
    //# the Cumulative Acknowledgment field results in a sequence wraparound that affects the
    //# ordering between the Cumulative Acknowledgment field and the state variable recover.
    // Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //= https://www.rfc-editor.org/rfc/rfc6582#section-6
    //= type=test
    //= reason=Ordinary no-SACK NewReno (default) only; not selectable Reno or negotiated-SACK RACK/PRR recovery. Timeout guard tested at ordinary and wrapping sequence boundaries.
    //# When three or more duplicate acknowledgments are received, the Cumulative
    //# Acknowledgment field doesn't cover more than recover, and a new fast recovery is not
    //# invoked, the sender should follow the guidance in Section 4.
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=on_timeout halves supplied FlightSize with two-MSS floor on first timeout; repeated same-segment timeout keeps threshold. Helper asserts 10000 flight -> 5000 threshold, repeat at flight=2000 -> unchanged 5000; minimum floor separately asserted by sack_timeout_boundary_and_cancel_preserve_epoch. ECN sharing is a separate RFC3168 policy.
    //# When a TCP sender detects segment loss using the retransmission timer and the given
    //# segment has not yet been resent by way of the retransmission timer, the value of
    //# ssthresh MUST be set to no more than the value given in equation (4):
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Threshold helper uses actual eligible flight /2 with two-MSS minimum; timeout vectors assert 10000->5000 and SACK boundary vectors assert floor. Limited Transmit exclusion is caller-owned and separately evidenced.
    //# ssthresh = max (FlightSize / 2, 2*SMSS) (4)
    //= https://www.rfc-editor.org/rfc/rfc5681#section-3.1
    //= type=test
    //= reason=Repeated RTO for the same outstanding head retains ssthresh; timeout_marker_boundaries_and_wrap asserts threshold remains5000 after smaller-flight second timeout and resets for a new acknowledged flight. Caller timer/encode atomicity is separate.
    //# On the other hand, when a TCP sender detects segment loss using the retransmission timer
    //# and the given segment has already been retransmitted by way of the retransmission timer
    //# at least once, the value of ssthresh is held constant.
    fn timeout_marker_boundaries_and_wrap() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for end in [Seq(10_000), Seq(0), Seq(u32::MAX)] {
                let mut c =
                    Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
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
                assert_eq!(
                    c.on_ack(end.wrapping_add(1_001), 1_000, 2_999),
                    algorithm == RecoveryAlgorithm::NewReno
                );
                assert!(!c.on_ack(end.wrapping_add(4_000), 2_999, 0));
                c.on_timeout(8_000, end.wrapping_add(8_000));
                assert_eq!(c.ssthresh(), 4_000);
                c.on_ack(end.wrapping_add(8_001), 1, 7_999);
                assert!(three_duplicates(&mut c, 7_999, end.wrapping_add(16_000)));
                assert!(c.fast_recovery);
                let new_end = end.wrapping_add(20_000);
                c.on_timeout(11_999, new_end);
                assert!(!c.fast_recovery);
                assert_eq!(c.recover, Some(new_end));
                assert_eq!(c.cwnd(), 1_000);
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc5681#section-4.1
    //= type=test
    //= reason=restart_after_idle sets min(cwnd,selected IW), never increases a reduced cwnd; both algorithm choices assert reduced and grown values. iw10_transmit_idle_restart_and_data_rto covers the last-data idle trigger; default_initial_window_piecewise_boundaries and initial_window_uses_negotiated_effective_mss cover default IW calculation.
    //# For the purposes of this standard, we define RW = min(IW,cwnd).
    fn mss_idle_reset_and_saturation() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            let mut c = Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
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
            let mut c =
                Congestion::new(u32::MAX, algorithm, InitialWindow::default(), Seq(u32::MAX));
            assert_eq!(c.cwnd(), MAX_WINDOW);
            c.on_ack(Seq(1), u32::MAX, u32::MAX);
            assert_eq!(c.cwnd(), MAX_WINDOW);
            assert!(three_duplicates(&mut c, u32::MAX, Seq(10)));
            c.on_duplicate_ack(Seq(1), u32::MAX, Seq(10), false);
            assert_eq!((c.cwnd(), c.ssthresh()), (MAX_WINDOW, MAX_WINDOW));
            c.set_mss(u32::MAX);
            c.on_timeout(u32::MAX, Seq(10));
            assert_eq!((c.cwnd(), c.ssthresh()), (MAX_WINDOW, MAX_WINDOW));
            let mut c = Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
            c.on_duplicate_ack(Seq(1), 4_000, Seq(4_000), false);
            c.on_duplicate_ack(Seq(1), 4_000, Seq(4_000), false);
            c.reset_duplicate_acks();
            assert!(three_duplicates(&mut c, 4_000, Seq(4_000)));
        }
    }

    #[test]
    #[should_panic]
    fn zero_mss_rejected() {
        Congestion::new(
            0,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
            Seq(u32::MAX),
        );
    }

    #[test]
    #[should_panic]
    fn zero_mss_update_rejected() {
        Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
            Seq(u32::MAX),
        )
        .set_mss(0);
    }
    #[test]
    fn ecn_retransmission_loss_and_ack_boundaries_wrap() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(100), Seq(u32::MAX - 12_499)] {
                for acked_retransmission in [0, 500, 1000] {
                    let end = base.wrapping_add(16_000);
                    let mut c =
                        Congestion::new(1000, algorithm, InitialWindow::default(), Seq(u32::MAX));
                    assert!(c.on_ecn(base, 16_000, end));
                    assert_eq!(c.ssthresh(), 8000);
                    assert!(three_duplicates(&mut c, 16_000, end));
                    c.on_retransmit(base.wrapping_add(1000));
                    assert_eq!(
                        c.on_ack(base.wrapping_add(12_000), 12_000, 4000),
                        algorithm == RecoveryAlgorithm::NewReno
                    );
                    c.on_retransmit(base.wrapping_add(13_000));
                    // A shorter retransmission must not forget still-outstanding bytes.
                    c.on_retransmit(base.wrapping_add(12_500));
                    if acked_retransmission != 0 {
                        assert_eq!(
                            c.on_ack(
                                base.wrapping_add(12_000 + acked_retransmission),
                                acked_retransmission,
                                4000 - acked_retransmission
                            ),
                            algorithm == RecoveryAlgorithm::NewReno
                        );
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
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5
    //= type=test
    //= reason=TCP sender reduction only: helper asserts cwnd/threshold reduction, mixed loss/ECN epoch and no duplicate response; connection asserts repeated ECE and no ECN-driven retransmission. Generic non-TCP transports are not provided.
    //# Upon the receipt by an ECN-Capable transport of a single CE packet,
    //# the congestion control algorithms followed at the end-systems MUST be
    //# essentially the same as the congestion control response to a *single*
    //# dropped packet.
    // Actor/condition: TCP sender/congestion controller; single CE indication in eligible original-flight epoch.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= type=test
    //= reason=Negotiated non-SACK Reno/NewReno: ecn_duplicate_and_advancing_ack_growth_boundaries asserts entry/later duplicate-ECE suppression and advancing/non-ECE contrasts; ecn_duplicate_entry_below_threshold_and_covering_ack_exit traces successive reductions to cwnd<ssthresh, capped ECE entry and covering-ECE exit, normal non-ECE exit and preserved wire retransmission. No general inherited recovery-compliance claim.
    //# The sending
    //# TCP SHOULD NOT increase the congestion window in response to the
    //# receipt of an ECN-Echo ACK packet.
    // Actor/condition: TCP sender/congestion controller; accepted ECE ACK.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= type=test
    //= reason=Reno/NewReno helper epoch/threshold assertions plus connection emitted-retransmission-versus-pending-loss RTO assertions. No router congestion-detection claim.
    //# TCP should not react to congestion indications more than once every window of data (or more loosely, more than once every round-trip time). That is, the TCP sender's congestion window should be reduced only once in response to a series of dropped and/or CE packets from a single window of data. In addition, the TCP source should not decrease the slow-start threshold, ssthresh, if it has been decreased within the last round trip time. However, if any retransmitted packets are dropped, then this is interpreted by the source TCP as a new instance of congestion.
    // Actor/condition: TCP endpoint; mixed ECN/loss epoch and lost retransmission.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5
    //= type=test
    //= reason=Original-flight reduction epoch assertions combine ECN and actual loss; retransmission loss remains a new event, as refined in section 6.1.2.
    //# An additional goal is that the end-systems should react to congestion at most once per window of data (i.e., at most once per round-trip time), to avoid reacting multiple times to multiple indications of congestion within a round-trip time.
    // Actor/condition: TCP endpoint; multiple indications within original-flight epoch.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
    //= type=test
    //= reason=Congestion helper asserts cwnd/threshold values after eligible ECN and mixed-loss epochs; one-MSS timer rate reduction is separately audited.
    //# That is, the TCP source halves the congestion window "cwnd" and reduces the slow start threshold "ssthresh".
    // Actor/condition: TCP endpoint; eligible ECE ACK.
    fn ecn_loss_recovery_shares_reduction_but_not_retransmission() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(0), Seq(u32::MAX - 3_999)] {
                let end = base.wrapping_add(4_000);
                let mut c =
                    Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
                assert!(c.on_ecn(base, 4_000, end));
                assert_eq!((c.cwnd(), c.ssthresh()), (2_000, 2_000));
                assert!(!c.on_ecn(end, 4_000, end));
                // A real loss in the ECN window still fast retransmits, without
                // a second threshold reduction (flight is intentionally smaller).
                assert!(three_duplicates(&mut c, 2_000, end));
                assert_eq!(c.ssthresh(), 2_000);
                assert!(!c.on_ecn(base, 2_000, end));
                assert_eq!(
                    c.on_ack_with_ecn(base.wrapping_add(1_000), 1_000, 1_000, true),
                    algorithm == RecoveryAlgorithm::NewReno
                );
                assert!(!c.on_ack_with_ecn(end, 1_000, 0, true));
                assert!(!c.fast_recovery);
                assert!(!c.on_ecn(end, 2_000, end));
                assert!(c.on_ecn(end.wrapping_add(1), 2_000, end.wrapping_add(2_000)));

                let mut c =
                    Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
                assert!(three_duplicates(&mut c, 8_000, end));
                let threshold = c.ssthresh();
                assert!(!c.on_ecn(end, 8_000, end));
                assert_eq!(c.ssthresh(), threshold);
                c.on_timeout(2_000, end);
                assert_eq!(c.cwnd(), 1_000);
                assert!(!c.on_ecn(end, 2_000, end));

                let mut c =
                    Congestion::new(1_000, algorithm, InitialWindow::default(), Seq(u32::MAX));
                assert!(c.on_ecn(base, 8_000, end));
                let threshold = c.ssthresh();
                c.on_timeout(2_000, end);
                assert_eq!(c.ssthresh(), threshold);
                assert_eq!(c.cwnd(), 1_000);
            }
        }
    }
}

#[cfg(test)]
mod cubic_tests;
