use super::*;

fn context(end: Seq, rtt: Option<u64>, paced: bool) -> StartupAck {
    StartupAck {
        rtt,
        snd_nxt: end,
        paced,
    }
}

fn round(h: &mut HyStart, base: Seq, rtt: u64, ticks: u64) -> bool {
    let end = base.wrapping_add(10);
    let mut exit = false;
    for n in 1..=10 {
        let (_, done) = h.ack(
            base.wrapping_add(n),
            context(end, Some(rtt), false),
            1,
            1,
            CallerTimebase {
                units_per_second: ticks,
                ..CallerTimebase::default()
            },
        );
        exit |= done;
    }
    exit
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
//= type=test
//= reason=Together with threshold and cap/division tests, asserts published fixed constants, five-round limit including partial entry, wrap and us/ns clocks.
//# MIN_RTT_THRESH = 4 msec
//# MAX_RTT_THRESH = 16 msec
//# MIN_RTT_DIVISOR = 8
//# N_RTT_SAMPLE = 8
//# CSS_GROWTH_DIVISOR = 4
//# CSS_ROUNDS = 5
//# L = infinity if paced, L = 8 if non-paced
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
//= type=test
//= reason=Together with threshold and cap/division tests, asserts published fixed constants, five-round limit including partial entry, wrap and us/ns clocks.
//# It is RECOMMENDED that a HyStart++ implementation use the following
//# constants:
fn delay_css_fallback_and_five_rounds_include_entry_partial_round() {
    for base in [Seq(0), Seq(u32::MAX - 4)] {
        for scale in [1, 1000] {
            let mut h = HyStart::default();
            assert!(!round(&mut h, base, 100_000 * scale, 1_000_000 * scale));
            assert!(!round(
                &mut h,
                base.wrapping_add(10),
                113_000 * scale,
                1_000_000 * scale
            ));
            assert_eq!(h.css_rounds, 1);
            assert_eq!(h.baseline, Some(113_000 * scale));
            assert!(!round(
                &mut h,
                base.wrapping_add(20),
                112_000 * scale,
                1_000_000 * scale
            ));
            assert_eq!(h.baseline, None);
            assert_eq!(h.css_rounds, 0);
            assert!(!round(
                &mut h,
                base.wrapping_add(30),
                127_000 * scale,
                1_000_000 * scale
            ));
            for n in 4..7 {
                assert!(!round(
                    &mut h,
                    base.wrapping_add(n * 10),
                    127_000 * scale,
                    1_000_000 * scale
                ));
            }
            assert!(round(
                &mut h,
                base.wrapping_add(70),
                127_000 * scale,
                1_000_000 * scale
            ));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
//= type=test
//= reason=Seven fresh samples cannot trigger entry/fallback; None cannot count; 4ms/interior/16ms threshold vectors.
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
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
//= type=test
//= reason=Seven fresh samples cannot trigger entry/fallback; None cannot count; 4ms/interior/16ms threshold vectors.
//# For CSS rounds where at least N_RTT_SAMPLE RTT samples have been
//# obtained, check to see if the current round's minRTT drops below
//# baseline (cssBaselineMinRtt) indicating that slow start exit was
//# spurious:
//#
//# if (currentRoundMinRTT < cssBaselineMinRtt)
//# cssBaselineMinRtt = infinity
//# resume slow start including HyStart++
fn eight_fresh_samples_threshold_clamps_and_no_cached_samples() {
    for (last, threshold) in [(1_000, 4_000), (80_000, 10_000), (1_000_000, 16_000)] {
        let mut h = HyStart::default();
        round(&mut h, Seq(0), last, 1_000_000);
        let tb = CallerTimebase::default();
        for n in 11..=17 {
            h.ack(
                Seq(n),
                context(Seq(100), Some(last + threshold), false),
                0,
                1000,
                tb,
            );
        }
        assert_eq!(h.baseline, None);
        for n in 18..25 {
            h.ack(Seq(n), context(Seq(100), None, false), 0, 1000, tb);
        }
        assert_eq!(h.samples, 7);
        h.ack(
            Seq(25),
            context(Seq(100), Some(last + threshold), false),
            0,
            1000,
            tb,
        );
        assert_eq!(h.baseline, Some(last + threshold));
        // Seven lower samples alone cannot resume SS in a fresh CSS round.
        h.ack(Seq(100), context(Seq(200), None, false), 0, 1000, tb);
        for n in 101..108 {
            h.ack(Seq(n), context(Seq(200), Some(last), false), 0, 1000, tb);
        }
        assert!(h.baseline.is_some());
        h.ack(Seq(108), context(Seq(200), Some(last), false), 0, 1000, tb);
        assert_eq!(h.baseline, None);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
//= type=test
//= reason=CSS one-byte ACK credit equals whole-byte credit with divisor four across the retained remainder.
//# The minimum value of CSS_GROWTH_DIVISOR MUST be at least 2.
fn delayed_ack_cap_division_fraction_mss_and_actual_pacing() {
    let tb = CallerTimebase::default();
    for mss in [1, 500, 1000, 9000] {
        let mut h = HyStart::default();
        let end = Seq(mss * 20);
        assert_eq!(
            h.ack(end, context(end, None, false), mss * 20, mss, tb).0,
            mss * 8
        );
        assert_eq!(
            h.ack(end, context(end, None, true), mss * 20, mss, tb).0,
            mss * 20
        );
        h.sent(end, false); // Protocol bypass does not qualify as paced.
        assert_eq!(
            h.ack(end, context(end, None, true), mss * 20, mss, tb).0,
            mss * 8
        );
    }
    let mut whole = HyStart {
        baseline: Some(100),
        ..HyStart::default()
    };
    let mut divided = whole.clone();
    let total = whole
        .ack(Seq(1000), context(Seq(2000), None, false), 999, 1000, tb)
        .0;
    let mut sum = 0;
    for n in 1..=999 {
        sum += divided
            .ack(Seq(n), context(Seq(2000), None, false), 1, 1000, tb)
            .0;
    }
    assert_eq!(sum, total);
    assert_eq!(divided.fraction, whole.fraction);
}

#[test]
fn committed_boundary_is_not_extended_by_new_output() {
    let mut h = HyStart::default();
    let tb = CallerTimebase::default();
    h.ack(Seq(1), context(Seq(10), Some(100), false), 0, 1000, tb);
    h.sent(Seq(20), true);
    h.ack(Seq(9), context(Seq(20), Some(100), true), 0, 1000, tb);
    assert_eq!(h.window_end, Some(Seq(10)));
    h.ack(Seq(10), context(Seq(20), Some(100), true), 0, 1000, tb);
    assert_eq!(h.window_end, Some(Seq(20)));
    assert_eq!(h.last_min, Some(100));
    assert_eq!(h.samples, 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
//= type=test
//= reason=Asserts unavailable initial minima, no sample from None, descending/mixed minima and rotation to unavailable after an unsampled round.
//# lastRoundMinRTT and currentRoundMinRTT are initialized to infinity at
//# the initialization time.  currRTT is the RTT sampled from the latest
//# incoming ACK and initialized to infinity.
//#
//# lastRoundMinRTT = infinity
//# currentRoundMinRTT = infinity
//# currRTT = infinity
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.2
//= type=test
//= reason=Asserts unavailable initial minima, no sample from None, descending/mixed minima and rotation to unavailable after an unsampled round.
//# At the start of each round during standard slow start [RFC5681] and
//# CSS, initialize the variables used to compute the last round's and
//# current round's minimum RTT:
//#
//# lastRoundMinRTT = currentRoundMinRTT
//# currentRoundMinRTT = infinity
//# rttSampleCount = 0
fn unavailable_rtt_initialization_and_round_minima() {
    let mut h = HyStart::default();
    assert_eq!((h.last_min, h.current_min, h.baseline), (None, None, None));
    assert_eq!((h.samples, h.css_rounds, h.fraction), (0, 0, 0));
    let tb = CallerTimebase::default();
    h.ack(Seq(1), context(Seq(10), None, false), 1, 1000, tb);
    assert_eq!((h.last_min, h.current_min, h.samples), (None, None, 0));
    for (ack, rtt) in [(2, 110), (3, 90), (4, 100)] {
        h.ack(Seq(ack), context(Seq(10), Some(rtt), false), 0, 1000, tb);
    }
    assert_eq!((h.current_min, h.samples), (Some(90), 3));
    h.ack(Seq(10), context(Seq(20), None, false), 0, 1000, tb);
    assert_eq!((h.last_min, h.current_min, h.samples), (Some(90), None, 0));
    h.ack(Seq(20), context(Seq(20), None, false), 0, 1000, tb);
    assert_eq!((h.last_min, h.current_min, h.samples), (None, None, 0));
}
