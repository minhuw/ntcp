use super::*;

fn state(cwnd: u32, mss: u32) -> Cubic {
    let mut c = Cubic::new(CallerTimebase::default());
    c.congestion(cwnd * 10 / 7);
    c.start_epoch(cwnd, mss);
    c
}

#[test]
fn cube_root_and_curve_reference_vectors() {
    for value in [0, 1, 2, 7, 8, 9, 27, 1000, (1u128 << 96) - 1, u128::MAX] {
        let root = u128::from(cube_root(value));
        assert!(root.pow(3) <= value);
        assert!(root + 1 > value / (root + 1) / (root + 1));
    }
    let mut c = Cubic::new(CallerTimebase::default());
    c.congestion(10_000);
    c.start_epoch(7000, 1000);
    assert!(
        c.k as u128 * 1_000_000 / TIME_SCALE > 1_957_000
            && c.k as u128 * 1_000_000 / TIME_SCALE < 1_958_000
    );
    assert_eq!(c.window(c.k as u64, 1000), 10_000 * WINDOW_SCALE);
    assert_eq!(
        c.window(c.k as u64 + TIME_SCALE as u64, 1000),
        10_400 * WINDOW_SCALE
    );
    assert_eq!(
        c.window(c.k as u64 - TIME_SCALE as u64, 1000),
        9600 * WINDOW_SCALE
    );
    // Integer cube-root rounding perturbs the epoch origin by <0.01 byte.
    assert!(c.window(0, 1000).abs_diff(7000 * WINDOW_SCALE) < WINDOW_SCALE / 100);
}

#[test]
fn published_per_ack_cubic_rule_not_reported_erratum_9186() {
    let mut single = state(7000, 1000);
    single.elapsed = 3_000_000;
    single.rtt = 100_000;
    single.acked = 1000;
    let mut delayed = single.clone();
    delayed.acked = 2000;
    let mut small = single.clone();
    small.acked = 1;
    // Concave/convex increments are per new ACK, including sub-MSS ACKs.
    assert_eq!(single.grow(7000, 1000), 7500);
    assert_eq!(delayed.grow(7000, 1000), 7500);
    assert_eq!(small.grow(7000, 1000), 7500);
    assert!(
        (delayed.w_est - 7000 * WINDOW_SCALE).abs_diff(2 * (single.w_est - 7000 * WINDOW_SCALE))
            <= 1
    );
    // Same delivered bytes in two new ACKs yield two cubic increments.
    assert!(single.grow(7500, 1000) > 7500);
}

#[test]
fn reno_friendly_byte_counting_alpha_switch_and_fractional_growth() {
    let mut c = state(7000, 1000);
    c.acked = 1000;
    let expected = 7000 * WINDOW_SCALE + 1000 * 1000 * WINDOW_SCALE * 9 / (7000 * 17);
    assert_eq!(c.grow(7000, 1000), (expected / WINDOW_SCALE) as u32);
    assert_eq!(c.w_est, expected);
    c.w_est = u128::from(c.cwnd_prior) * WINDOW_SCALE;
    c.acked = 1000;
    let prior = c.cwnd_prior;
    assert_eq!(c.grow(prior, 1000), prior + 1000 * 1000 / prior);

    let mut whole = Cubic::new(CallerTimebase::default());
    whole.acked = 2000;
    let mut divided = whole.clone();
    divided.acked = 1;
    let expected = whole.grow(10_000, 1000);
    let mut cwnd = 10_000;
    for _ in 0..2000 {
        cwnd = divided.grow(cwnd, 1000);
    }
    // Byte-counted AIMD is robust to ACK division (denominator changes as
    // cwnd grows, so the divided sequence is slightly more conservative).
    assert_eq!(expected, 10_200);
    assert!((10_190..=10_200).contains(&cwnd));

    // Small cubic increments accumulate below a byte instead of vanishing.
    let mut c = Cubic::new(CallerTimebase::default());
    c.start_epoch(1_000_000, 1000);
    c.acked = 1;
    c.elapsed = 1_000_000;
    c.rtt = 1_000_000;
    let mut cwnd = 1_000_000;
    for _ in 0..1000 {
        cwnd = c.grow(cwnd, 1000);
    }
    assert!(cwnd > 1_000_000);
}

#[test]
fn fast_convergence_and_timeout_epoch() {
    let mut c = Cubic::new(CallerTimebase::default());
    c.congestion(10_000);
    assert_eq!((c.w_max, c.cwnd_prior), (10_000, 10_000));
    c.congestion(9000);
    assert_eq!((c.w_max, c.cwnd_prior), (7650, 9000));
    c.start_epoch(6300, 1000);
    assert!(c.k > 0);
    c.start_epoch(8000, 1000);
    assert!(c.k < 0); // W_max from fast convergence remains below cwnd_epoch.
    assert_eq!(c.w_max, 7650);
    assert!(c.window(0, 1000).abs_diff(8000 * WINDOW_SCALE) < WINDOW_SCALE / 100);
    c.timeout();
    c.start_epoch(8000, 1000);
    assert_eq!((c.k, c.w_max, c.w_est), (0, 8000, 8000 * WINDOW_SCALE));
    c.congestion(12_000);
    assert_eq!(c.w_max, 12_000);
}

#[test]
fn committed_full_flight_idle_exclusion_and_caller_timebases() {
    let mut results = alloc::vec::Vec::new();
    for scale in [1, 1000] {
        let mut c = Cubic::new(CallerTimebase {
            units_per_second: 1_000_000 * scale,
            ..CallerTimebase::default()
        });
        c.congestion(10_000);
        let base = Seq(u32::MAX - 3000);
        let end = base.wrapping_add(7000);
        c.sent(100 * scale, 6000, 7000, end, false, false);
        c.prepare_ack(
            200 * scale,
            Some(100 * scale),
            base.wrapping_add(1000),
            1000,
            true,
        );
        assert!(!c.can_grow()); // Unfilled cwnd never validates growth.
        c.sent(300 * scale, 7000, 7000, end, false, false);
        c.prepare_ack(
            100_300 * scale,
            Some(100_000 * scale),
            base.wrapping_add(2000),
            1000,
            true,
        );
        let first = c.grow(7000, 1000);
        c.prepare_ack(200_300 * scale, Some(100_000 * scale), end, 5000, true);
        let second = c.grow(first, 1000);
        assert_eq!(c.elapsed, 100_000 * scale);
        // The long idle gap and a later unfilled flight do not age CUBIC.
        c.sent(
            100_000_000 * scale,
            1000,
            second,
            end.wrapping_add(1000),
            false,
            false,
        );
        c.prepare_ack(
            100_100_000 * scale,
            Some(100_000 * scale),
            end.wrapping_add(1000),
            1000,
            true,
        );
        assert!(!c.can_grow());
        assert_eq!(c.grow(second, 1000), second);
        assert_eq!(c.elapsed, 100_000 * scale);
        c.sent(
            101_000_000 * scale,
            second,
            second,
            end.wrapping_add(second),
            false,
            false,
        );
        c.prepare_ack(
            101_100_000 * scale,
            Some(100_000 * scale),
            end.wrapping_add(2000),
            1000,
            true,
        );
        let third = c.grow(second, 1000);
        results.push((first, second, third, c.seconds(c.elapsed), c.k, c.w_est));
        assert_eq!(c.seconds(c.elapsed), (TIME_SCALE / 5) as u64);
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn mss_rebases_history_and_overflow_is_bounded() {
    let mut c = state(7000, 1000);
    c.mss_changed(1000, 500);
    assert_eq!((c.w_max, c.cwnd_prior), (5000, 5000));
    assert!(!c.epoch && !c.can_grow());
    c.start_epoch(3500, 500);
    assert!(
        c.k as u128 * 1_000_000 / TIME_SCALE > 1_957_000
            && c.k as u128 * 1_000_000 / TIME_SCALE < 1_958_000
    );
    c.mss_changed(500, 1000);
    assert_eq!(c.w_max, 5000);
    for mss in [1, 1000, MAX_WINDOW] {
        let mut c = Cubic::new(CallerTimebase::default());
        c.congestion(MAX_WINDOW);
        c.start_epoch(2, mss);
        assert!(c.window(0, mss) <= (3 + u128::from(mss) / 10000) * WINDOW_SCALE);
        assert_eq!(
            c.window(u64::MAX, mss),
            u128::from(MAX_WINDOW) * WINDOW_SCALE
        );
        c.elapsed = u64::MAX;
        c.rtt = u64::MAX;
        c.acked = u32::MAX;
        assert!(c.grow(2, mss) <= MAX_WINDOW);
        c.acked = 1;
        assert_eq!(c.grow(MAX_WINDOW, mss), MAX_WINDOW);
    }
    // Finest AIMD byte increment at the maximum serial-safe window still
    // retains a positive fixed-point increment (including alpha=9/17).
    let mut c = Cubic::new(CallerTimebase::default());
    c.start_epoch(MAX_WINDOW - 1, 1);
    c.cwnd_prior = MAX_WINDOW;
    c.acked = 1;
    let before = c.w_est;
    c.grow(MAX_WINDOW - 1, 1);
    assert!(c.w_est > before);
}

#[test]
fn nonadvancing_receive_window_limit_freezes_clock() {
    let mut c = state(7000, 1000);
    c.sent(0, 7000, 7000, Seq(7000), false, false);
    c.receiver_limited(100_000);
    assert_eq!(c.elapsed, 100_000);
    c.prepare_ack(100_000_000, Some(100_000), Seq(1000), 1000, false);
    assert!(!c.can_grow());
    assert_eq!(c.elapsed, 100_000);
    c.sent(100_100_000, 7000, 7000, Seq(8000), false, false);
    c.prepare_ack(100_200_000, Some(100_000), Seq(2000), 1000, true);
    assert_eq!(c.elapsed, 200_000);
    assert!(c.can_grow());
}
