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
