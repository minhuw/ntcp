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
    minimum: u64,
}

// Partial evidence: estimator arithmetic and bounded backoff only. The connection selects
// unambiguous samples (Karn), manages timers, and retransmits; this helper alone does not
// establish RFC 6298 conformance.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
//# The RTO MUST be computed according to the algorithm in [10], including Karn's algorithm
//# for taking RTT samples (MUST-18).
impl RttEstimator {
    pub(crate) fn new(minimum: u64) -> Self {
        assert!((1..=MAX_RTO).contains(&minimum));
        Self {
            minimum,
            srtt: None,
            variance: 0,
            rto: MIN_RTO,
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
            .clamp(self.minimum, MAX_RTO);
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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum InitialWindow {
    #[default]
    Rfc5681,
    // Experimental RFC 6928 initial/restart window; loss windows stay one MSS.
    Iw10,
}

impl InitialWindow {
    fn bytes(self, mss: u32) -> u32 {
        let (segments, cap) = match self {
            Self::Rfc5681 => (4, 4_380),
            Self::Iw10 => (10, 14_600),
        };
        mss.saturating_mul(segments)
            .min(mss.saturating_mul(2).max(cap))
            .min(MAX_WINDOW)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Congestion {
    algorithm: RecoveryAlgorithm,
    initial_window: InitialWindow,
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    acknowledged: u64,
    duplicate_acks: u8,
    // Exclusive SND.NXT, not the inclusive highest byte used in RFC 6582.
    recover: Option<Seq>,
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
    pub(crate) fn new(
        mss: u32,
        algorithm: RecoveryAlgorithm,
        initial_window: InitialWindow,
    ) -> Self {
        assert!(mss > 0);
        let mss = mss.min(MAX_WINDOW);
        Self {
            algorithm,
            initial_window,
            mss,
            cwnd: initial_window.bytes(mss),
            ssthresh: MAX_WINDOW,
            acknowledged: 0,
            duplicate_acks: 0,
            recover: None,
            fast_recovery: false,
            sack_recovery: false,
            ecn_end: None,
            tlp_reduction_end: None,
            timeout_retransmitted: false,
            retransmitted_end: None,
        }
    }

    pub(crate) fn initial_window(&self) -> u32 {
        self.initial_window.bytes(self.mss)
    }

    // SYN negotiation selects the byte bound anew; path changes preserve segment counts.
    pub(crate) fn set_initial_mss(&mut self, mss: u32, syn_timed_out: bool) {
        self.set_mss(mss);
        self.cwnd = if syn_timed_out {
            self.mss
        } else {
            self.initial_window()
        };
    }

    pub(crate) fn cwnd(&self) -> u32 {
        self.cwnd
    }

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
                self.acknowledged = 0;
            }
            return false;
        }
        if self.fast_recovery {
            if self.algorithm == RecoveryAlgorithm::Reno && relation.is_some() {
                // Retain recover and the independent ECN epoch: exiting fast recovery
                // must not allow a second reduction for the same flight.
                //= https://www.rfc-editor.org/rfc/rfc5681#section-3.2
                //# When the next ACK arrives that acknowledges previously
                //# unacknowledged data, a TCP MUST set cwnd to ssthresh (the value
                //# set in step 2).
                self.cwnd = self.ssthresh;
                self.fast_recovery = false;
                self.acknowledged = 0;
                return false;
            }
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

    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Chooses the congestion target from flight, preserving shared ECN/TLP epochs. PRR entry and flight snapshot orchestration are caller-owned.
    //# ssthresh = CongCtrlAlg()  // Target cwnd after recovery
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=Recovery/ECN/TLP epochs prevent repeated original-flight reductions; retransmission losses use a separate additional response.
    //# If multiple original transmissions or retransmissions were lost in a
    //# window, the congestion control specified in [RFC5681] only reacts
    //# once per window.
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

    pub(crate) fn cancel_sack_recovery(&mut self) {
        self.sack_recovery = false;
        self.acknowledged = 0;
    }

    // The caller checks RFC 5681's duplicate-ACK eligibility conditions.
    pub(crate) fn on_duplicate_ack(&mut self, flight: u32, highest_sent: Seq) -> bool {
        if self.sack_recovery {
            return false;
        }
        if self.fast_recovery {
            self.cwnd = self.cwnd.saturating_add(self.mss).min(MAX_WINDOW);
            return false;
        }
        self.duplicate_acks = self.duplicate_acks.saturating_add(1);
        if self.duplicate_acks != 3 || self.recover.is_some() {
            return false;
        }
        if self.ecn_end.is_none() && self.tlp_reduction_end.is_none() {
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
        self.cwnd = (self.cwnd / 2).max(self.mss).min(self.ssthresh);
        self.acknowledged = 0;
        self.ecn_end = Some(highest_sent);
        true
    }

    fn reduce_threshold(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(self.mss.saturating_mul(2)).min(MAX_WINDOW);
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

    pub(crate) fn on_timeout(&mut self, flight: u32, highest_sent: Seq) {
        // Repeated RTOs for the same unacknowledged segment retain ssthresh.
        // RFC 3168 section 6.1.2: loss of a retransmission is new congestion,
        // even inside the ECN epoch. An original-flight loss shares its reduction.
        if !self.timeout_retransmitted
            && ((self.ecn_end.is_none() && self.tlp_reduction_end.is_none())
                || self.retransmitted_end.is_some())
        {
            self.reduce_threshold(flight);
        }
        self.ecn_end = None;
        self.tlp_reduction_end = None;
        self.timeout_retransmitted = true;
        self.recover = Some(highest_sent);
        self.fast_recovery = false;
        self.sack_recovery = false;
        self.cwnd = self.mss;
        self.acknowledged = 0;
        self.reset_duplicate_acks();
    }

    pub(crate) fn reset_duplicate_acks(&mut self) {
        self.duplicate_acks = 0;
    }

    pub(crate) fn restart_after_idle(&mut self) {
        self.cwnd = self.cwnd.min(self.initial_window());
        self.acknowledged = 0;
        self.reset_duplicate_acks();
    }
}

// RFC 6937 section 3, Conservative Reduction Bound (byte units).
//= https://www.rfc-editor.org/rfc/rfc6937#section-1
//= reason=Byte-unit CRB selection only; no SSRB implementation and no claim that initial credit satisfies strict packet conservation.
//# We describe two slightly different Reduction Bound algorithms:
//# Conservative Reduction Bound (CRB), which is strictly packet
//# conserving; and a Slow Start Reduction Bound (SSRB), which is more
//# aggressive than CRB by, at most, 1 segment per ACK.
//= https://www.rfc-editor.org/rfc/rfc6937#section-8
//= reason=Byte-unit CRB selection only; no SSRB implementation and no claim that initial credit satisfies strict packet conservation.
//# Implementers that change PRR from counting bytes to segments have to
//# be cautious about the effects of ACK splitting attacks [Savage99],
//# where the receiver acknowledges partial segments for the purpose of
//# confusing the sender's congestion accounting.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Prr {
    recover_fs: u32,
    delivered: u64,
    out: u64,
    credit: u32,
}

impl Prr {
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Initializes byte counters and caller-supplied flight; initial MSS credit is a separate policy, not evidence of strict CRB entry conformance.
    //# At the beginning of recovery, initialize PRR state.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Initializes byte counters and caller-supplied flight; initial MSS credit is a separate policy, not evidence of strict CRB entry conformance.
    //# prr_delivered = 0         // Total bytes delivered during recovery
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Initializes byte counters and caller-supplied flight; initial MSS credit is a separate policy, not evidence of strict CRB entry conformance.
    //# prr_out = 0               // Total bytes sent during recovery
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Initializes byte counters and caller-supplied flight; initial MSS credit is a separate policy, not evidence of strict CRB entry conformance.
    //# RecoverFS = snd.nxt-snd.una // FlightSize at the start of recovery
    pub(crate) fn new(flight: u32, mss: u32) -> Self {
        Self {
            recover_fs: flight.max(1),
            delivered: 0,
            out: 0,
            credit: mss,
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Byte-budget equations only, with nonnegative saturation and widened ceiling arithmetic. Caller supplies delivery, pipe and threshold; entry guarantee can override this bound.
    //# if (pipe > ssthresh) {
    //#    // Proportional Rate Reduction
    //#    sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Byte-budget equations only, with nonnegative saturation and widened ceiling arithmetic. Caller supplies delivery, pipe and threshold; entry guarantee can override this bound.
    //# if (conservative) {    // PRR-CRB
    //#   limit = prr_delivered - prr_out
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Byte-budget equations only, with nonnegative saturation and widened ceiling arithmetic. Caller supplies delivery, pipe and threshold; entry guarantee can override this bound.
    //# // Attempt to catch up, as permitted by limit
    //# sndcnt = MIN(ssthresh - pipe, limit)
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3.1
    //= reason=Byte-budget equations only, with nonnegative saturation and widened ceiling arithmetic. Caller supplies delivery, pipe and threshold; entry guarantee can override this bound.
    //# Transmission is controlled
    //# by the sending limit, which is set to prr_delivered - prr_out.
    //= https://www.rfc-editor.org/rfc/rfc8985#section-9.3
    //= reason=PRR-CRB accounts newly delivered bytes and pipe against threshold; no claim of CRB/SSRB alternatives beyond implemented CRB.
    //# The Proportional Rate
    //# Reduction (PRR) algorithm [RFC6937] is RECOMMENDED for the specific
    //# congestion control actions taken upon the losses detected by RACK-
    //# TLP.
    pub(crate) fn acknowledge(&mut self, delivered: u32, pipe: u32, threshold: u32) {
        // Duplicate ACKs cannot add delivery, but must not revoke unspent
        // credit (including after failed output). Recompute the cumulative bound.
        self.delivered = self.delivered.saturating_add(u64::from(delivered));
        let allowed = if pipe > threshold {
            (u128::from(self.delivered) * u128::from(threshold))
                .div_ceil(u128::from(self.recover_fs))
                .min(u128::from(u64::MAX)) as u64
        } else {
            self.delivered
                .min(self.out.saturating_add(u64::from(threshold - pipe)))
        };
        self.credit = allowed.saturating_sub(self.out).min(u64::from(u32::MAX)) as u32;
    }

    // Entry policy, not an RFC 6937 CRB equation: this may permit out > delivered.
    // The section 3/4 entry and conservation TODOs deliberately remain open.
    pub(crate) fn guarantee_initial(&mut self, mss: u32) {
        self.credit = self.credit.max(mss);
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> (u32, u64, u64) {
        (self.recover_fs, self.delivered, self.out)
    }

    pub(crate) fn credit(&self) -> u32 {
        self.credit
    }

    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= reason=Accounts actual bytes supplied by caller and consumes credit. Caller must enforce bytes <= credit and commit only after successful output; this helper does not enforce the sending bound.
    //# On any data transmission or retransmission:
    //#
    //#    prr_out += (data sent) // strictly less than or equal to sndcnt
    pub(crate) fn sent(&mut self, bytes: u32) {
        self.out = self.out.saturating_add(u64::from(bytes));
        self.credit = self.credit.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Checks proportional budget, CRB headroom, actual sent subtraction, duplicate ACK with no further credit, and timer-entry accounting; does not validate connection delivery epoch.
    //# if (pipe > ssthresh) {
    //#    // Proportional Rate Reduction
    //#    sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Checks proportional budget, CRB headroom, actual sent subtraction, duplicate ACK with no further credit, and timer-entry accounting; does not validate connection delivery epoch.
    //# if (conservative) {    // PRR-CRB
    //#   limit = prr_delivered - prr_out
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Checks proportional budget, CRB headroom, actual sent subtraction, duplicate ACK with no further credit, and timer-entry accounting; does not validate connection delivery epoch.
    //# // Attempt to catch up, as permitted by limit
    //# sndcnt = MIN(ssthresh - pipe, limit)
    fn prr_crb_proportional_conservative_bound_and_no_duplicate_credit() {
        let mut prr = Prr::new(10_000, 1000);
        prr.acknowledge(3000, 7000, 5000);
        assert_eq!(prr.credit(), 1500);
        prr.sent(1000);
        assert_eq!(prr.credit(), 500);
        prr.acknowledge(1000, 3000, 5000);
        assert_eq!(prr.credit(), 2000);
        prr.sent(2000);
        // The two emitted MSS raise pipe from 3000 to 5000. An unchanged
        // duplicate ACK supplies no further credit at the threshold.
        prr.acknowledge(0, 5000, 5000);
        assert_eq!(prr.credit(), 0);
        prr.acknowledge(1000, 1000, 5000);
        assert_eq!(prr.credit(), 2000);
        let mut timer_entry = Prr::new(10_000, 1000);
        timer_entry.sent(1000);
        timer_entry.acknowledge(1000, 3000, 5000);
        // Initial retransmission consumes actual output even without an entry ACK.
        assert_eq!(timer_entry.credit(), 0);
        let mut timer_entry = Prr::new(10_000, 1000);
        timer_entry.acknowledge(1000, 3000, 5000); // Real deferred causative SACK.
        timer_entry.guarantee_initial(1000);
        timer_entry.sent(1000);
        timer_entry.acknowledge(1000, 3000, 5000);
        assert_eq!(timer_entry.credit(), 1000);
        timer_entry.sent(1000);
        timer_entry.acknowledge(0, 3000, 5000);
        assert_eq!(timer_entry.credit(), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-4
    //= type=test
    //= reason=Checks repeated zero-delivery updates retain unspent credit in both branches; delivery/out counters stay unchanged until successful sent. Helper simulation, not an application-stall integration test.
    //# The missed opportunities to send
    //# due to stalls are treated like banked voluntary window reductions;
    //# specifically, they cause prr_delivered - prr_out to be significantly
    //# positive.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Checks repeated zero-delivery updates retain unspent credit in both branches; delivery/out counters stay unchanged until successful sent. Helper simulation, not an application-stall integration test.
    //# On every ACK during recovery compute:
    //#
    //#    DeliveredData = change_in(snd.una) + change_in(SACKd)
    //#    prr_delivered += DeliveredData
    fn prr_duplicate_ack_preserves_banked_credit_without_minting_delivery() {
        for (pipe, expected) in [(7000, 1500), (3000, 2000)] {
            let mut prr = Prr::new(10_000, 1000);
            prr.acknowledge(3000, pipe, 5000);
            assert_eq!(prr.credit(), expected);
            for _ in 0..4 {
                // also the state after repeated failed output
                prr.acknowledge(0, pipe, 5000);
                assert_eq!(prr.credit(), expected);
                assert_eq!(prr.delivered, 3000);
                assert_eq!(prr.out, 0);
            }
            prr.sent(1000);
            // Reflect the successful retransmission in pipe. The proportional
            // bound stays constant above threshold; CRB recomputes headroom.
            prr.acknowledge(0, pipe + 1000, 5000);
            assert_eq!(prr.credit(), if pipe > 5000 { 500 } else { 1000 });
            assert_eq!(prr.delivered, 3000);
            assert_eq!(prr.out, 1000);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Independent byte-budget vectors only; convergence tests the equation at delivered=RecoverFS, not connection exit. No network ACK-splitting proof.
    //# if (pipe > ssthresh) {
    //#    // Proportional Rate Reduction
    //#    sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Independent byte-budget vectors only; convergence tests the equation at delivered=RecoverFS, not connection exit. No network ACK-splitting proof.
    //# if (conservative) {    // PRR-CRB
    //#   limit = prr_delivered - prr_out
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Independent byte-budget vectors only; convergence tests the equation at delivered=RecoverFS, not connection exit. No network ACK-splitting proof.
    //# // Attempt to catch up, as permitted by limit
    //# sndcnt = MIN(ssthresh - pipe, limit)
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Independent byte-budget vectors only; convergence tests the equation at delivered=RecoverFS, not connection exit. No network ACK-splitting proof.
    //# On any data transmission or retransmission:
    //#
    //#    prr_out += (data sent) // strictly less than or equal to sndcnt
    //= https://www.rfc-editor.org/rfc/rfc6937#section-4
    //= type=test
    //= reason=Independent byte-budget vectors only; convergence tests the equation at delivered=RecoverFS, not connection exit. No network ACK-splitting proof.
    //# If there are minimal losses, PRR will converge to exactly the target
    //# window chosen by the congestion control algorithm.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-8
    //= type=test
    //= reason=Independent byte-budget vectors only; convergence tests the equation at delivered=RecoverFS, not connection exit. No network ACK-splitting proof.
    //# Implementers that change PRR from counting bytes to segments have to
    //# be cautious about the effects of ACK splitting attacks [Savage99],
    //# where the receiver acknowledges partial segments for the purpose of
    //# confusing the sender's congestion accounting.
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
            let mut prr = Prr::new(flight, 1000);
            prr.sent(out);
            prr.acknowledge(delivered, pipe, threshold);
            assert_eq!(prr.credit(), expected);
            assert_eq!(prr.delivered, u64::from(delivered));
            assert_eq!(prr.out, u64::from(out));
            prr.sent(expected);
            assert_eq!(prr.credit(), 0);
            assert_eq!(prr.out, u64::from(out) + u64::from(expected));
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Characterizes zero counters, flight retention and initial-MSS override exceeding delivered bytes; explicitly exposes a strict-bound gap, not a passing conformance assertion.
    //# At the beginning of recovery, initialize PRR state.
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Characterizes zero counters, flight retention and initial-MSS override exceeding delivered bytes; explicitly exposes a strict-bound gap, not a passing conformance assertion.
    //# prr_delivered = 0         // Total bytes delivered during recovery
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Characterizes zero counters, flight retention and initial-MSS override exceeding delivered bytes; explicitly exposes a strict-bound gap, not a passing conformance assertion.
    //# prr_out = 0               // Total bytes sent during recovery
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Characterizes zero counters, flight retention and initial-MSS override exceeding delivered bytes; explicitly exposes a strict-bound gap, not a passing conformance assertion.
    //# RecoverFS = snd.nxt-snd.una // FlightSize at the start of recovery
    //= https://www.rfc-editor.org/rfc/rfc6937#section-4
    //= type=test
    //= reason=Characterizes zero counters, flight retention and initial-MSS override exceeding delivered bytes; explicitly exposes a strict-bound gap, not a passing conformance assertion.
    //# Under all conditions and sequences of events during recovery, PRR-CRB
    //# strictly bounds the data transmitted to be equal to or less than the
    //# amount of data delivered to the receiver.
    fn prr_initial_state_and_guarantee_are_not_delivery() {
        let mut prr = Prr::new(10_000, 1000);
        assert_eq!((prr.recover_fs, prr.delivered, prr.out), (10_000, 0, 0));
        assert_eq!(prr.credit(), 1000); // Characterize policy, not a CRB waiver.
        prr.acknowledge(0, 3000, 5000);
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
            let mut c = Congestion::new(1000, RecoveryAlgorithm::NewReno, InitialWindow::Iw10);
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
        let mut c = Congestion::new(1000, RecoveryAlgorithm::NewReno, InitialWindow::Iw10);
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
    fn configurable_rto_floor_keeps_initial_and_backoff_bounds() {
        for minimum in [1, 200_000, 1_000_000, MAX_RTO] {
            let mut rtt = RttEstimator::new(minimum);
            assert_eq!(rtt.rto(), 1_000_000);
            rtt.sample(100_000);
            assert_eq!(rtt.rto(), 300_000u64.max(minimum));
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
            let mut c = Congestion::new(1000, RecoveryAlgorithm::NewReno, InitialWindow::Iw10);
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
    fn tlp_loss_response_shares_ecn_and_recovery_epoch_guards() {
        let mut c = Congestion::new(1000, RecoveryAlgorithm::NewReno, InitialWindow::Iw10);
        assert!(c.on_ecn(Seq(1), 8000, Seq(8001)));
        assert_eq!(c.ssthresh(), 4000);
        assert!(c.on_sack_recovery(Seq(7001), 2000, Seq(8001)));
        assert_eq!(c.ssthresh(), 4000); // do not halve again inside ECN epoch
        assert!(!c.on_sack_recovery(Seq(7001), 2000, Seq(8001)));
        c.cancel_sack_recovery();
        assert!(!c.on_sack_recovery(Seq(7001), 2000, Seq(8001)));
    }

    #[test]
    fn iw10_bounds_mss_changes_timeout_and_idle_restart() {
        for (mss, window) in [
            (1_000, 10_000),
            (1_460, 14_600),
            (3_000, 14_600),
            (8_000, 16_000),
            (u32::MAX, MAX_WINDOW),
        ] {
            for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
                let mut c = Congestion::new(mss, algorithm, InitialWindow::Iw10);
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
        let mut c = Congestion::new(3_000, RecoveryAlgorithm::default(), InitialWindow::Iw10);
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
    fn initial_slow_start_and_byte_counting() {
        for (mss, window) in [(500, 2_000), (1_000, 4_000), (1_460, 4_380), (3_000, 6_000)] {
            assert_eq!(
                Congestion::new(mss, RecoveryAlgorithm::default(), InitialWindow::default()).cwnd(),
                window
            );
        }
        let mut c = Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
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
        assert!(!c.on_duplicate_ack(flight, end));
        assert!(!c.on_duplicate_ack(flight, end));
        c.on_duplicate_ack(flight, end)
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Congestion target selection only: asserts SACK entry threshold and shared ECN epoch; not PRR sending or entry conservation.
    //# ssthresh = CongCtrlAlg()  // Target cwnd after recovery
    fn sack_entry_partial_and_full_ack() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(0), Seq(u32::MAX - 3_999)] {
                for extra in [0, 1] {
                    let end = base.wrapping_add(8_000);
                    let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
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
        );
        assert!(three_duplicates(&mut c, 8_000, Seq(8_000)));
        assert!(!c.on_sack_recovery(Seq(8_000), 2_000, Seq(12_000)));
        assert!(c.fast_recovery);
        assert!(!c.sack_recovery);
        assert_eq!(c.cwnd(), 7_000);
    }

    #[test]
    fn sack_timeout_boundary_and_cancel_preserve_epoch() {
        for end in [Seq(10_000), Seq(0), Seq(u32::MAX)] {
            let mut c = Congestion::new(
                1_000,
                RecoveryAlgorithm::default(),
                InitialWindow::default(),
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
    //= https://www.rfc-editor.org/rfc/rfc6937#section-3
    //= type=test
    //= reason=Congestion target selection only: asserts SACK entry threshold and shared ECN epoch; not PRR sending or entry conservation.
    //# ssthresh = CongCtrlAlg()  // Target cwnd after recovery
    fn sack_ecn_epoch_shares_only_current_reduction() {
        for base in [Seq(0), Seq(u32::MAX - 3_999)] {
            let end = base.wrapping_add(16_000);
            for extra in [0, 1] {
                let mut c = Congestion::new(
                    1_000,
                    RecoveryAlgorithm::default(),
                    InitialWindow::default(),
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
                assert_eq!(c.ssthresh(), if acked < 3_000 { 7_000 } else { 8_000 });
                assert!(!c.sack_recovery);
                assert_eq!(c.cwnd(), 1_000);
            }
        }
    }

    #[test]
    fn newreno_partial_and_full_ack() {
        let mut c = Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
        );
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
    fn reno_and_newreno_recovery_exit() {
        assert_eq!(RecoveryAlgorithm::default(), RecoveryAlgorithm::NewReno);
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(0), Seq(u32::MAX - 3_999)] {
                for acked in [500, 2_000, 8_000, 9_000] {
                    let end = base.wrapping_add(8_000);
                    let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
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
    fn timeout_marker_boundaries_and_wrap() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for end in [Seq(10_000), Seq(0), Seq(u32::MAX)] {
                let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
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
            }
        }
    }

    #[test]
    fn mss_idle_reset_and_saturation() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
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
            let mut c = Congestion::new(u32::MAX, algorithm, InitialWindow::default());
            assert_eq!(c.cwnd(), MAX_WINDOW);
            c.on_ack(Seq(1), u32::MAX, u32::MAX);
            assert_eq!(c.cwnd(), MAX_WINDOW);
            assert!(three_duplicates(&mut c, u32::MAX, Seq(10)));
            c.on_duplicate_ack(u32::MAX, Seq(10));
            assert_eq!((c.cwnd(), c.ssthresh()), (MAX_WINDOW, MAX_WINDOW));
            c.set_mss(u32::MAX);
            c.on_timeout(u32::MAX, Seq(10));
            assert_eq!((c.cwnd(), c.ssthresh()), (MAX_WINDOW, MAX_WINDOW));
            let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
            c.on_duplicate_ack(4_000, Seq(4_000));
            c.on_duplicate_ack(4_000, Seq(4_000));
            c.reset_duplicate_acks();
            assert!(three_duplicates(&mut c, 4_000, Seq(4_000)));
        }
    }

    #[test]
    #[should_panic]
    fn zero_mss_rejected() {
        Congestion::new(0, RecoveryAlgorithm::default(), InitialWindow::default());
    }

    #[test]
    #[should_panic]
    fn zero_mss_update_rejected() {
        Congestion::new(
            1_000,
            RecoveryAlgorithm::default(),
            InitialWindow::default(),
        )
        .set_mss(0);
    }
    #[test]
    fn ecn_retransmission_loss_and_ack_boundaries_wrap() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(100), Seq(u32::MAX - 12_499)] {
                for acked_retransmission in [0, 500, 1000] {
                    let end = base.wrapping_add(16_000);
                    let mut c = Congestion::new(1000, algorithm, InitialWindow::default());
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
    fn ecn_loss_recovery_shares_reduction_but_not_retransmission() {
        for algorithm in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
            for base in [Seq(0), Seq(u32::MAX - 3_999)] {
                let end = base.wrapping_add(4_000);
                let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
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

                let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
                assert!(three_duplicates(&mut c, 8_000, end));
                let threshold = c.ssthresh();
                assert!(!c.on_ecn(end, 8_000, end));
                assert_eq!(c.ssthresh(), threshold);
                c.on_timeout(2_000, end);
                assert_eq!(c.cwnd(), 1_000);
                assert!(!c.on_ecn(end, 2_000, end));

                let mut c = Congestion::new(1_000, algorithm, InitialWindow::default());
                assert!(c.on_ecn(base, 8_000, end));
                let threshold = c.ssthresh();
                c.on_timeout(2_000, end);
                assert_eq!(c.ssthresh(), threshold);
                assert_eq!(c.cwnd(), 1_000);
            }
        }
    }
}
