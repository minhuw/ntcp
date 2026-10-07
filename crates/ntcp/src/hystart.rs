//! RFC 9406 initial slow start. Times are unsmoothed caller-clock ticks.
use core::cmp::Ordering;

use crate::{connection::CallerTimebase, seq::Seq};

#[derive(Clone, Copy, Debug)]
pub(crate) struct StartupAck {
    pub(crate) rtt: Option<u64>,
    pub(crate) snd_nxt: Seq,
    pub(crate) paced: bool,
}

#[derive(Clone, Debug, Default)]
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
//= reason=None represents infinity/unavailable RTT; ACK context never substitutes cached SRTT.
//# lastRoundMinRTT and currentRoundMinRTT are initialized to infinity at
//# the initialization time.  currRTT is the RTT sampled from the latest
//# incoming ACK and initialized to infinity.
//#
//# lastRoundMinRTT = infinity
//# currentRoundMinRTT = infinity
//# currRTT = infinity
pub(crate) struct HyStart {
    window_end: Option<Seq>,
    unpaced_end: Option<Seq>,
    last_min: Option<u64>,
    current_min: Option<u64>,
    samples: u8,
    baseline: Option<u64>,
    css_rounds: u8,
    fraction: u8,
}

impl HyStart {
    #[cfg(test)]
    pub(crate) fn test_state(&self) -> (u8, Option<u64>, u8, Option<Seq>) {
        (
            self.samples,
            self.baseline,
            self.css_rounds,
            self.window_end,
        )
    }

    pub(crate) fn sent(&mut self, end: Seq, paced: bool) {
        if !paced {
            self.unpaced_end = Some(end);
        }
    }

    // Called once per fresh delivery ACK, even when cwnd growth is disallowed.
    // The boundary ACK belongs to the round it completes. An empty-flight
    // boundary is armed from committed SND.NXT on the next arriving ACK.
    //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
    //= reason=Fixed published constants are applied below; no deployment-specific tuning profile is selected.
    //# MIN_RTT_THRESH = 4 msec
    //# MAX_RTT_THRESH = 16 msec
    //# MIN_RTT_DIVISOR = 8
    //# N_RTT_SAMPLE = 8
    //# CSS_GROWTH_DIVISOR = 4
    //# CSS_ROUNDS = 5
    //# L = infinity if paced, L = 8 if non-paced
    //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
    //= reason=Fixed published constants are applied below; no deployment-specific tuning profile is selected.
    //# It is RECOMMENDED that a HyStart++ implementation use the following
    //# constants:
    pub(crate) fn ack(
        &mut self,
        ack: Seq,
        context: StartupAck,
        eligible_bytes: u32,
        mss: u32,
        timebase: CallerTimebase,
    ) -> (u32, bool) {
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Round edge uses committed SND.NXT and serial comparisons; empty-flight arming waits for fresh delivery, never SYN timing.
        //# HyStart++ measures rounds using sequence numbers, as follows:
        //#
        //# *  Define windowEnd as a sequence number initialized to SND.NXT.
        //#
        //# *  When windowEnd is ACKed, the current round ends and windowEnd is
        //# set to SND.NXT.
        let end = *self.window_end.get_or_insert(context.snd_nxt);
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Eligible newly acknowledged bytes are capped at eight SMSS unless actually paced, including bypass-flight tracking.
        //# The following pseudocode uses a limit, L, to control the
        //# aggressiveness of the cwnd increase during both standard slow start
        //# and CSS.  While an arriving ACK may newly acknowledge an arbitrary
        //# number of bytes, the HyStart++ algorithm limits the number of those
        //# bytes applied to increase the cwnd to L*SMSS bytes.
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Eligible newly acknowledged bytes are capped at eight SMSS unless actually paced, including bypass-flight tracking.
        //# For each arriving ACK in slow start, where N is the number of
        //# previously unacknowledged bytes acknowledged in the arriving ACK:
        //#
        //# Update the cwnd:
        //#
        //# cwnd = cwnd + min(N, L * SMSS)
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
        //= reason=Eligible newly acknowledged bytes are capped at eight SMSS unless actually paced, including bypass-flight tracking.
        //# A paced TCP implementation SHOULD use L =
        //# infinity.
        let bytes = if context.paced && self.unpaced_end.is_none() {
            eligible_bytes
        } else {
            eligible_bytes.min(mss.saturating_mul(8))
        };
        if self.unpaced_end.is_some_and(|end| {
            matches!(
                ack.serial_cmp(end),
                Some(Ordering::Equal | Ordering::Greater)
            )
        }) {
            self.unpaced_end = None;
        }
        // Entry ACK grows in standard SS; fallback ACK still grows in CSS.
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=CSS divides byte credit by four and retains fractional bytes; no fixed per-ACK growth.
        //# For each arriving ACK in CSS, where N is the number of previously
        //# unacknowledged bytes acknowledged in the arriving ACK:
        //#
        //# Update the cwnd:
        //#
        //# cwnd = cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR)
        //= https://www.rfc-editor.org/rfc/rfc9406#section-6
        //= reason=CSS divides byte credit by four and retains fractional bytes; no fixed per-ACK growth.
        //# The ACK division attack outlined in [SCWA99] does not affect
        //# HyStart++ because the congestion window increase in HyStart++ is
        //# based on the number of bytes newly acknowledged in each arriving ACK
        //# rather than by a particular constant on each arriving ACK.
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
        //= reason=CSS divides byte credit by four and retains fractional bytes; no fixed per-ACK growth.
        //# The minimum value of CSS_GROWTH_DIVISOR MUST be at least 2.
        let increase = if self.baseline.is_some() {
            let credit = u64::from(bytes) + u64::from(self.fraction);
            self.fraction = (credit % 4) as u8;
            (credit / 4) as u32
        } else {
            bytes
        };
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Each fresh raw ACK sample updates the round minimum once in SS or CSS; unavailable samples do not count.
        //# Keep track of the minimum observed RTT:
        //#
        //# currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
        //# rttSampleCount += 1
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Each fresh raw ACK sample updates the round minimum once in SS or CSS; unavailable samples do not count.
        //# cwnd = cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR)
        //#
        //# Keep track of the minimum observed RTT:
        //#
        //# currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
        //# rttSampleCount += 1
        if let Some(rtt) = context.rtt {
            self.current_min = Some(self.current_min.map_or(rtt, |min| min.min(rtt)));
            self.samples = self.samples.saturating_add(1);
            //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
            //= reason=Eight fresh samples and two valid minima gate entry; last/8 is clamped to caller-clock 4..16ms.
            //# For rounds where at least N_RTT_SAMPLE RTT samples have been obtained
            //# and currentRoundMinRTT and lastRoundMinRTT are valid, check to see if
            //# delay increase triggers slow start exit:
            //#
            //# if ((rttSampleCount >= N_RTT_SAMPLE) AND
            //# (currentRoundMinRTT != infinity) AND
            //# (lastRoundMinRTT != infinity))
            //# RttThresh = max(MIN_RTT_THRESH,
            //# min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
            //# if (currentRoundMinRTT >= (lastRoundMinRTT + RttThresh))
            //# cssBaselineMinRtt = currentRoundMinRTT
            //# exit slow start and enter CSS
            if self.samples >= 8 {
                let current = self.current_min.unwrap();
                if let Some(baseline) = self.baseline {
                    //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
                    //= reason=CSS fallback uses eight current-round samples, clears baseline/count/fraction, and preserves sequence-round boundaries.
                    //# For CSS rounds where at least N_RTT_SAMPLE RTT samples have been
                    //# obtained, check to see if the current round's minRTT drops below
                    //# baseline (cssBaselineMinRtt) indicating that slow start exit was
                    //# spurious:
                    //#
                    //# if (currentRoundMinRTT < cssBaselineMinRtt)
                    //# cssBaselineMinRtt = infinity
                    //# resume slow start including HyStart++
                    //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
                    //= reason=CSS fallback uses eight current-round samples, clears baseline/count/fraction, and preserves sequence-round boundaries.
                    //# In application-limited scenarios, the amount of data in flight could
                    //# fall below the bandwidth-delay product (BDP) and result in smaller
                    //# RTT samples, which can trigger an exit back to slow start.  It is
                    //# expected that a connection might oscillate between CSS and slow start
                    //# in such scenarios.  But this behavior will neither result in a
                    //# connection prematurely entering congestion avoidance nor cause
                    //# overshooting compared to slow start.
                    if current < baseline {
                        self.baseline = None;
                        self.css_rounds = 0;
                        self.fraction = 0;
                    }
                } else if let Some(last) = self.last_min {
                    let units = u128::from(timebase.units_per_second);
                    let lower = (units * 4).div_ceil(1000) as u64;
                    let upper = (units * 16).div_ceil(1000) as u64;
                    let threshold = (last / 8).clamp(lower, upper);
                    if current.saturating_sub(last) >= threshold {
                        self.baseline = Some(current);
                        self.css_rounds = 0;
                    }
                }
            }
        }
        if matches!(
            ack.serial_cmp(end),
            Some(Ordering::Equal | Ordering::Greater)
        ) {
            if self.baseline.is_some() {
                //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
                //= reason=The partial entry round counts towards five completed CSS rounds.
                //# CSS lasts at most CSS_ROUNDS rounds.  If the transition into CSS
                //# happens in the middle of a round, that partial round counts towards
                //# the limit.
                self.css_rounds += 1; // The entry partial round counts.
                if self.css_rounds == 5 {
                    return (increase, true);
                }
            }
            //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
            //= reason=Completing ACK contributes before rotation; next round starts with no RTT and zero samples.
            //# At the start of each round during standard slow start [RFC5681] and
            //# CSS, initialize the variables used to compute the last round's and
            //# current round's minimum RTT:
            //#
            //# lastRoundMinRTT = currentRoundMinRTT
            //# currentRoundMinRTT = infinity
            //# rttSampleCount = 0
            self.last_min = self.current_min;
            self.current_min = None;
            self.samples = 0;
            self.window_end = (context.snd_nxt.serial_cmp(ack) == Some(Ordering::Greater))
                .then_some(context.snd_nxt);
        }
        (increase, false)
    }
}

#[cfg(test)]
mod tests;
