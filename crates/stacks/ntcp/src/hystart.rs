//! RFC 9406 initial slow start. Times are unsmoothed caller-clock ticks.
use crate::{connection::CallerTimebase, seq::Seq};

// Explicit non-paced startup policy: admit credit for coalesced ACKs up to
// sixteen segments. RFC9406 section4.3 permits tuning its recommended eight;
// this trades a larger bounded burst for faster stretch-ACK window growth.
const UNPACED_ACK_LIMIT: u32 = 16;

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
    //= reason=Published RTT/CSS constants retained; non-paced L is explicitly tuned to16 under section4.3, independently of actual pacing provenance.
    //# MIN_RTT_THRESH = 4 msec
    //# MAX_RTT_THRESH = 16 msec
    //# MIN_RTT_DIVISOR = 8
    //# N_RTT_SAMPLE = 8
    //# CSS_GROWTH_DIVISOR = 4
    //# CSS_ROUNDS = 5
    //# L = infinity if paced, L = 8 if non-paced
    //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
    //= reason=Published RTT/CSS constants retained; non-paced L is explicitly tuned to16 under section4.3, independently of actual pacing provenance.
    //# It is RECOMMENDED that a HyStart++ implementation use the following
    //# constants:
    //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
    //= reason=Selected L16 tuning improves credit for coalesced ACKs while retaining a finite non-paced bound. Larger bursts and loss are a policy tradeoff, not a claim of measured performance improvement.
    //# An implementation MAY tune them for different
    //# network characteristics.
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
        let end = self.window_end.unwrap_or(context.snd_nxt);
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Eligible newly acknowledged bytes use tuned L=16 unless actually paced; bypassed output retains the finite limit.
        //# The following pseudocode uses a limit, L, to control the
        //# aggressiveness of the cwnd increase during both standard slow start
        //# and CSS.  While an arriving ACK may newly acknowledge an arbitrary
        //# number of bytes, the HyStart++ algorithm limits the number of those
        //# bytes applied to increase the cwnd to L*SMSS bytes.
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
        //= reason=Eligible newly acknowledged bytes use tuned L=16 unless actually paced; bypassed output retains the finite limit.
        //# For each arriving ACK in slow start, where N is the number of
        //# previously unacknowledged bytes acknowledged in the arriving ACK:
        //#
        //# Update the cwnd:
        //#
        //# cwnd = cwnd + min(N, L * SMSS)
        //= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
        //= reason=Eligible newly acknowledged bytes use tuned L=16 unless actually paced; bypassed output retains the finite limit.
        //# A paced TCP implementation SHOULD use L =
        //# infinity.
        let bytes = if context.paced && self.unpaced_end.is_none() {
            eligible_bytes
        } else {
            eligible_bytes.min(mss.saturating_mul(UNPACED_ACK_LIMIT))
        };
        if self.unpaced_end.is_some_and(|end| ack.at_or_after(end)) {
            self.unpaced_end = None;
        }
        // A flight delivered by the first ACK in its round supplies at
        // most one sample. It cannot enter CSS, and the next round starts
        // empty. Keep the resulting minimum without opening a round.
        if self.window_end.is_none() && ack == context.snd_nxt && self.baseline.is_none() {
            debug_assert!(self.current_min.is_none() && self.samples == 0);
            self.last_min = context.rtt;
            return (bytes, false);
        }
        self.window_end = Some(end);
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
        if ack.at_or_after(end) {
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
            self.window_end = context.snd_nxt.after(ack).then_some(context.snd_nxt);
        }
        (increase, false)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fast_path_tests {
    use super::*;

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct ReferenceHyStart {
        window_end: Option<Seq>,
        unpaced_end: Option<Seq>,
        last_min: Option<u64>,
        current_min: Option<u64>,
        samples: u8,
        baseline: Option<u64>,
        css_rounds: u8,
        fraction: u8,
    }

    impl ReferenceHyStart {
        fn sent(&mut self, end: Seq, paced: bool) {
            if !paced {
                self.unpaced_end = Some(end);
            }
        }

        // Exact pre-optimization HyStart::ack without the empty-round drain shortcut.
        fn ack(
            &mut self,
            ack: Seq,
            context: StartupAck,
            eligible_bytes: u32,
            mss: u32,
            timebase: CallerTimebase,
        ) -> (u32, bool) {
            let end = *self.window_end.get_or_insert(context.snd_nxt);
            let bytes = if context.paced && self.unpaced_end.is_none() {
                eligible_bytes
            } else {
                eligible_bytes.min(mss.saturating_mul(UNPACED_ACK_LIMIT))
            };
            if self.unpaced_end.is_some_and(|end| ack.at_or_after(end)) {
                self.unpaced_end = None;
            }
            let increase = if self.baseline.is_some() {
                let credit = u64::from(bytes) + u64::from(self.fraction);
                self.fraction = (credit % 4) as u8;
                (credit / 4) as u32
            } else {
                bytes
            };
            if let Some(rtt) = context.rtt {
                self.current_min = Some(self.current_min.map_or(rtt, |min| min.min(rtt)));
                self.samples = self.samples.saturating_add(1);
                if self.samples >= 8 {
                    let current = self.current_min.unwrap();
                    if let Some(baseline) = self.baseline {
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
            if ack.at_or_after(end) {
                if self.baseline.is_some() {
                    self.css_rounds += 1;
                    if self.css_rounds == 5 {
                        return (increase, true);
                    }
                }
                self.last_min = self.current_min;
                self.current_min = None;
                self.samples = 0;
                self.window_end = context.snd_nxt.after(ack).then_some(context.snd_nxt);
            }
            (increase, false)
        }
    }

    fn snapshot(h: &HyStart) -> ReferenceHyStart {
        ReferenceHyStart {
            window_end: h.window_end,
            unpaced_end: h.unpaced_end,
            last_min: h.last_min,
            current_min: h.current_min,
            samples: h.samples,
            baseline: h.baseline,
            css_rounds: h.css_rounds,
            fraction: h.fraction,
        }
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
        fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }
    }

    #[test]
    fn ack_fast_path_matches_base_over_random_sequences() {
        let mut fast_hits = 0usize;
        let mut css_entered = 0usize;
        let mut css_fallbacks = 0usize;
        let mut css_exits = 0usize;

        for seed in 1..=250u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut fast = HyStart::default();
            let mut base = ReferenceHyStart::default();
            let mut una = match rng.below(3) {
                0 => Seq(u32::MAX - 2000),
                1 => Seq(rng.next() as u32),
                _ => Seq(1000),
            };
            let mut nxt = una;
            let mss: u32 = [64, 536, 1200, 1460][rng.below(4) as usize];
            let timebase = CallerTimebase {
                units_per_second: [1_000, 1_000_000, 1_000_000_000][rng.below(3) as usize],
                ..CallerTimebase::default()
            };
            let ms = (u128::from(timebase.units_per_second) / 1000).max(1) as u64;
            let mut base_rtt = 10 * ms;
            // Alternate between small draining flights (fast path), bulk slow-start
            // rounds (CSS entry / fallback / exit), and mixed random traffic.
            let mode = seed % 3;

            for _ in 0..220 {
                if mode == 1 {
                    // Bulk slow-start mode: keep enough segments in flight for >= 8
                    // RTT samples per round so CSS entry, fallback, and exit occur.
                    while nxt.distance_from(una) < mss.saturating_mul(12) {
                        let len = 1 + rng.below(u64::from(mss)) as u32;
                        nxt = nxt.wrapping_add(len);
                        let paced = rng.chance(50);
                        fast.sent(nxt, paced);
                        base.sent(nxt, paced);
                    }
                } else {
                    // Send 0..3 segments to create empty, single-packet, and multi-packet flights.
                    let sends = if una == nxt {
                        1 + rng.below(3)
                    } else {
                        rng.below(3)
                    };
                    for _ in 0..sends {
                        let len = 1 + rng.below(u64::from(mss) * 2) as u32;
                        nxt = nxt.wrapping_add(len);
                        let paced = rng.chance(50);
                        fast.sent(nxt, paced);
                        base.sent(nxt, paced);
                    }
                }

                // Choose either a full-flight draining ACK or a partial ACK.
                let span = nxt.distance_from(una);
                if span == 0 {
                    continue;
                }
                let ack = if mode == 1 {
                    if rng.chance(4) {
                        nxt
                    } else {
                        let max_step = (span / 10).max(1).min(mss);
                        let step = 1 + rng.below(u64::from(max_step)) as u32;
                        una.wrapping_add(step)
                    }
                } else if rng.chance(45) {
                    nxt
                } else {
                    let step = 1 + rng.below(u64::from(span)) as u32;
                    una.wrapping_add(step)
                };
                let acked = ack.distance_from(una);
                let eligible = match rng.below(4) {
                    0 => 0,
                    1 => acked,
                    2 => acked.saturating_add(mss * 20),
                    _ => rng.below(u64::from(mss) * 24) as u32,
                };
                // Vary RTT regimes so baseline transitions between None, Some, fallback, and exit.
                if mode == 1 {
                    if fast.baseline.is_none() {
                        if fast.last_min.is_some() && rng.chance(25) {
                            base_rtt = 40 * ms;
                        } else if fast.last_min.is_none() {
                            base_rtt = 10 * ms;
                        }
                    } else if seed % 2 == 1 {
                        if rng.chance(8) {
                            base_rtt = 10 * ms;
                        }
                    } else {
                        base_rtt = 44 * ms;
                    }
                } else if rng.chance(15) {
                    base_rtt = [10 * ms, 40 * ms, 5 * ms, 80 * ms][rng.below(4) as usize];
                }
                let rtt = if rng.chance(12) {
                    None
                } else {
                    Some(base_rtt.saturating_add(rng.below(3 * ms + 1)))
                };
                let context = StartupAck {
                    rtt,
                    snd_nxt: nxt,
                    paced: rng.chance(50),
                };

                let will_hit_fast =
                    fast.window_end.is_none() && ack == context.snd_nxt && fast.baseline.is_none();
                let had_baseline = fast.baseline.is_some();

                let got = fast.ack(ack, context, eligible, mss, timebase);
                let expected = base.ack(ack, context, eligible, mss, timebase);
                assert_eq!(got, expected, "seed {seed}: return mismatch");
                assert_eq!(snapshot(&fast), base, "seed {seed}: state mismatch");

                if will_hit_fast {
                    fast_hits += 1;
                }
                if !had_baseline && fast.baseline.is_some() {
                    css_entered += 1;
                }
                if had_baseline && fast.baseline.is_none() {
                    css_fallbacks += 1;
                }
                una = ack;
                if got.1 {
                    css_exits += 1;
                    break;
                }
            }
        }

        assert!(fast_hits > 1000, "fast path rarely hit: {fast_hits}");
        assert!(css_entered > 20, "CSS rarely entered: {css_entered}");
        assert!(
            css_fallbacks > 5,
            "CSS fallback rarely hit: {css_fallbacks}"
        );
        assert!(css_exits > 10, "CSS exit rarely hit: {css_exits}");
    }
}
