use super::*;

fn state(cwnd: u32, mss: u32) -> Cubic {
    let mut c = Cubic::new(CallerTimebase::default());
    c.congestion(cwnd * 10 / 7);
    c.start_epoch(cwnd, mss);
    c
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.1
//= type=test
//= reason=Independent cube-root floor bounds, signed curve origin and +/-one second +/-400 byte vectors establish C=0.4 at MSS1000.
//# *  _C_: Constant that determines the aggressiveness of CUBIC in
//# competing with other congestion control algorithms in high-BDP
//# networks.  Please see Section 5 for more explanation on how it is
//# set.  The unit for _C_ is
//#
//# segment
//# ───────
//# 3
//# second
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Independent cube-root floor bounds, signed curve origin and +/-one second +/-400 byte vectors establish C=0.4 at MSS1000.
//# *  _K_: The time period in seconds it takes to increase the
//# congestion window size at the beginning of the current congestion
//# avoidance stage to _W_max_.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Independent cube-root floor bounds, signed curve origin and +/-one second +/-400 byte vectors establish C=0.4 at MSS1000.
//# *  W_cubic(_t_): The congestion window in segments at time _t_ in
//# seconds based on the cubic increase function, as described in
//# Section 4.2.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
//= type=test
//= reason=Independent cube-root floor bounds, signed curve origin and +/-one second +/-400 byte vectors establish C=0.4 at MSS1000.
//# CUBIC uses the following window increase function:
//#
//# 3
//# W     (t) = C * (t - K)  + W
//# cubic                      max
//#
//# Figure 1
//#
//# where _t_ is the elapsed time in seconds from the beginning of the
//# current congestion avoidance stage -- that is,
//#
//# t = t        - t
//# current    epoch
//#
//# and where _t_epoch_ is the time at which the current congestion
//# avoidance stage starts.  _K_ is the time period that the above
//# function takes to increase the congestion window size at the
//# beginning of the current congestion avoidance stage to _W_max_ if
//# there are no further congestion events.  _K_ is calculated using the
//# following equation:
//#
//# ┌────────────────┐
//# 3  │W    - cwnd
//# ╲  │ max       epoch
//# K =  ╲ │────────────────
//# ╲│       C
//#
//# Figure 2
//#
//# where _cwnd_epoch_ is the congestion window at the beginning of the
//# current congestion avoidance stage.
//= https://www.rfc-editor.org/rfc/rfc9438#section-5.1
//= type=test
//= reason=Independent cube-root floor bounds, signed curve origin and +/-one second +/-400 byte vectors establish C=0.4 at MSS1000.
//# However, it is NOT
//# RECOMMENDED to set _C_ to a very low value like 0.04, since CUBIC
//# with a low _C_ cannot efficiently use the bandwidth in fast and long-
//# distance networks.
//= https://www.rfc-editor.org/rfc/rfc9438#section-5.1
//= type=test
//= reason=Independent cube-root floor bounds, signed curve origin and +/-one second +/-400 byte vectors establish C=0.4 at MSS1000.
//# Therefore, _C_ SHOULD be set to 0.4.
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
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# The unit of all window sizes in this document is segments of the
//# SMSS, and the unit of all times is seconds.  Implementations can use
//# bytes to express window sizes, which would require factoring in the
//# SMSS wherever necessary and replacing _segments_acked_ (Figure 4)
//# with the number of acknowledged bytes.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# *  _W_est_: An estimate for the congestion window in segments in the
//# Reno-friendly region -- that is, an estimate for the congestion
//# window of Reno.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# *  _segments_acked_: Number of SMSS-sized segments acked when a "new
//# ACK" is received, i.e., an ACK that cumulatively acknowledges the
//# delivery of previously unacknowledged data.  This number will be a
//# decimal value when a new ACK acknowledges an amount of data that
//# is not SMSS-sized.  Specifically, it can be less than 1 when a new
//# ACK acknowledges a segment smaller than the SMSS.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# To summarize, CUBIC computes both W_cubic(_t_) and _W_est_ (see
//# Section 4.3) on receiving a new ACK in congestion avoidance and
//# chooses the larger of the two values.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# Thus, CUBIC uses Figure 4 to estimate the window size _W_est_ in the
//# Reno-friendly region with
//#
//# 1 - β
//# cubic
//# α      = 3 * ──────────
//# cubic       1 + β
//# cubic
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# _W_est_ is set equal to _cwnd_epoch_ at the start of the congestion
//# avoidance stage.  After that, on every new ACK, _W_est_ is updated
//# using Figure 4.  Note that this equation uses _segments_acked_ and
//# _cwnd_ is measured in segments.  An implementation that measures
//# _cwnd_ in bytes should adjust the equation accordingly using the
//# number of acknowledged bytes and the SMSS.  Also note that this
//# equation works for connections with enabled or disabled delayed ACKs
//# [RFC5681], as _segments_acked_ will be different based on the
//# segments actually acknowledged by a new ACK.
//#
//# segments_acked
//# W    = W    + α      * ──────────────
//# est    est    cubic        cwnd
//#
//# Figure 4
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# If so, CUBIC is in the
//# Reno-friendly region and _cwnd_ SHOULD be set to _W_est_ at each
//# reception of a new ACK.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.3
//= type=test
//= reason=Exact byte-scaled Figure4 at alpha9/17, switch to one at prior cwnd, delayed versus one-byte ACKs and fractional accumulation.
//# Once _W_est_ has grown to reach the _cwnd_ at the time of most
//# recently setting _ssthresh_ -- that is, _W_est_ >= _cwnd_prior_ --
//# the sender SHOULD set α__cubic_ to 1 to ensure that it can achieve
//# the same congestion window increment rate as Reno, which uses AIMD(1,
//# 0.5).
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
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Asserts pre-event cwnd, enabled 17/20 history and signed K; timeout origin is tested independently.
//# *  _cwnd_prior_: Size of _cwnd_ in segments at the time of setting
//# _ssthresh_ most recently, either upon exiting the first slow start
//# or just before _cwnd_ was reduced in the last congestion event.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Asserts pre-event cwnd, enabled 17/20 history and signed K; timeout origin is tested independently.
//# *  _W_max_: Size of _cwnd_ in segments just before _cwnd_ was reduced
//# in the last congestion event when fast convergence is disabled
//# (same as _cwnd_prior_ on a congestion event).  However, if fast
//# convergence is enabled, _W_max_ may be further reduced based on
//# the current saturation point.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.7
//= type=test
//= reason=Asserts pre-event cwnd, enabled 17/20 history and signed K; timeout origin is tested independently.
//# With fast convergence, when a congestion event occurs, _W_max_ is
//# updated as follows, before the window reduction described in
//# Section 4.6.
//#
//# ⎧       1 + β
//# ⎪            cubic
//# ⎪cwnd * ────────── if  cwnd < W     and fast convergence enabled,
//# W    = ⎨           2                  max
//# max   ⎪                  further reduce  W
//# ⎪                                   max
//# ⎩cwnd             otherwise, remember cwnd before reduction
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.7
//= type=test
//= reason=Asserts pre-event cwnd, enabled 17/20 history and signed K; timeout origin is tested independently.
//# To speed up this
//# bandwidth release by existing flows, the following fast convergence
//# mechanism SHOULD be implemented.
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

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-5.8
//= type=test
//= reason=Post-ACK underfill freezes clock immediately in us/ns, with no output or a delayed short suffix before RTO; historical full-flight ACKs retain credit, suffix receives none.
//# A flow is application limited if it is currently sending less than
//# what is allowed by the congestion window.  This can happen if the
//# flow is limited by either the sender application or the receiver
//# application (via the receiver's advertised window) and thus sends
//# less data than what is allowed by the sender's congestion window.
//= https://www.rfc-editor.org/rfc/rfc9438#section-5.8
//= type=test
//= reason=Post-ACK underfill freezes clock immediately in us/ns, with no output or a delayed short suffix before RTO; historical full-flight ACKs retain credit, suffix receives none.
//# CUBIC does not increase its congestion window if a flow is
//# application limited.  Per Section 4.2, it is required that _t_ in
//# Figure 1 not include application-limited periods, such as idle
//# periods; otherwise, W_cubic(_t_) might be very high after restarting
//# from these periods.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
//= type=test
//= reason=Post-ACK underfill freezes clock immediately in us/ns, with no output or a delayed short suffix before RTO; historical full-flight ACKs retain credit, suffix receives none.
//# The elapsed time _t_ in Figure 1 MUST NOT include periods during
//# which _cwnd_ has not been updated due to application-limited behavior
//# (see Section 5.8).
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Post-ACK underfill freezes clock immediately in us/ns, with no output or a delayed short suffix before RTO; historical full-flight ACKs retain credit, suffix receives none.
//# Implementations
//# that use _cwnd_ MUST use other measures to prevent _cwnd_ from
//# growing when the volume of bytes in flight is smaller than
//# _cwnd_.
fn short_application_suffix_pauses_clock_not_historical_ack_credit() {
    for scale in [1, 1000] {
        for suffix in [0, 500] {
            let mut c = Cubic::new(CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            });
            c.congestion(10_000);
            c.sent(0, 7000, 7000, Seq(7000), false, false);
            c.prepare_ack(
                100_000 * scale,
                Some(100_000 * scale),
                Seq(1000),
                1000,
                true,
            );
            let cwnd = c.grow(7000, 1000);
            c.ack_flight(6000, cwnd);
            assert_eq!(cwnd, 7075);
            assert!(!c.active);
            assert_eq!(c.limited_end, Some(Seq(7000)));
            // Either no output, or a delayed short suffix before the 1s RTO.
            if suffix != 0 {
                c.sent(
                    600_000 * scale,
                    6000 + suffix,
                    cwnd,
                    Seq(7000 + suffix),
                    false,
                    false,
                );
            }
            assert_eq!(c.elapsed, 0);
            c.prepare_ack(
                700_000 * scale,
                Some(100_000 * scale),
                Seq(2000),
                1000,
                true,
            );
            assert_eq!(c.slow_start_acked(), 1000);
            assert_eq!(c.elapsed, 0);
            let next = c.grow(cwnd, 1000);
            c.ack_flight(5000 + suffix, next);
            assert_eq!(next, 7150);
            c.prepare_ack(
                800_000 * scale,
                Some(100_000 * scale),
                Seq(7000 + suffix),
                5000 + suffix,
                true,
            );
            assert_eq!(c.slow_start_acked(), 5000); // Suffix earns no credit.
            assert_eq!(c.elapsed, 0);
            assert_eq!(c.grow(next, 1000), 7520);
        }
    }
}

#[test]
fn explicit_single_flow_fast_convergence_opt_out_and_lossless_epoch() {
    let mut c = Cubic::new(CallerTimebase::default());
    c.congestion(10_000);
    let mut single = c.clone();
    single.fast_convergence = false;
    c.congestion(8000);
    single.congestion(8000);
    assert_eq!((c.w_max, single.w_max), (6800, 8000));
    assert_eq!((c.cwnd_prior, single.cwnd_prior), (8000, 8000));
    c.startup_exit(12_345, 500);
    assert_eq!((c.cwnd_prior, c.w_max, c.k), (12_345, 12_345, 0));
    assert!(c.epoch);
    assert_eq!((c.k, c.w_max, c.w_est), (0, 12_345, 12_345 * WINDOW_SCALE));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=CA epoch begins at exiting ACK with W_est=cwnd_epoch and K=0; next CA ACK must not reset elapsed time.
//# *  _t_current_: Current time of the system in seconds.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=CA epoch begins at exiting ACK with W_est=cwnd_epoch and K=0; next CA ACK must not reset elapsed time.
//# *  _t_epoch_: The time in seconds at which the current congestion
//# avoidance stage started.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=CA epoch begins at exiting ACK with W_est=cwnd_epoch and K=0; next CA ACK must not reset elapsed time.
//# *  _cwnd_epoch_: The _cwnd_ at the beginning of the current
//# congestion avoidance stage, i.e., at time _t_epoch_.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.10
//= type=test
//= reason=CA epoch begins at exiting ACK with W_est=cwnd_epoch and K=0; next CA ACK must not reset elapsed time.
//# When CUBIC uses HyStart++ [RFC9406], it may exit the first slow start
//# without incurring any packet loss and thus _W_max_ is undefined.  In
//# this special case, CUBIC sets _cwnd_prior = cwnd_ and switches to
//# congestion avoidance.  It then increases its congestion window size
//# using Figure 1, where _t_ is the elapsed time since the beginning of
//# the current congestion avoidance stage, _K_ is set to 0, and _W_max_
//# is set to the congestion window size at the beginning of the current
//# congestion avoidance stage.
fn lossless_epoch_starts_at_exit_ack_not_first_ca_ack() {
    let mut c = Cubic::new(CallerTimebase::default());
    c.clock(100_000);
    c.startup_exit(20_000, 1000);
    assert_eq!((c.w_est, c.k, c.elapsed), (20_000 * WINDOW_SCALE, 0, 0));
    c.sent(110_000, 20_000, 20_000, Seq(20_000), false, false);
    c.prepare_ack(210_000, Some(100_000), Seq(1000), 1000, true);
    assert_eq!(c.elapsed, 100_000);
    c.grow(20_000, 1000);
    assert_eq!(c.elapsed, 100_000); // First CA ACK must not reset the exit epoch.
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Concave, equality/convex and larger-cwnd convex vectors assert per-new-ACK increment and retained fraction; upper/interior/lower targets explicit. Lower clamp uses an isolated arithmetic state, not a reachable-state claim.
//# *  _target_: Target value of the congestion window in segments after
//# the next RTT -- that is, W_cubic(_t_ + _RTT_), as described in
//# Section 4.2.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
//= type=test
//= reason=Concave, equality/convex and larger-cwnd convex vectors assert per-new-ACK increment and retained fraction; upper/interior/lower targets explicit. Lower clamp uses an isolated arithmetic state, not a reachable-state claim.
//# Upon receiving a new ACK during congestion avoidance, CUBIC computes
//# the _target_ congestion window size after the next _RTT_ using
//# Figure 1 as follows, where _RTT_ is the smoothed round-trip time.
//# The lower and upper bounds below ensure that CUBIC's congestion
//# window increase rate is non-decreasing and is less than the increase
//# rate of slow start [SXEZ19].
//#
//# ⎧
//# ⎪cwnd            if  W     (t + RTT) < cwnd
//# ⎪                     cubic
//# ⎨1.5 * cwnd      if  W     (t + RTT) > 1.5 * cwnd
//# target = ⎪                     cubic
//# ⎪W     (t + RTT) otherwise
//# ⎩ cubic
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.4
//= type=test
//= reason=Concave, equality/convex and larger-cwnd convex vectors assert per-new-ACK increment and retained fraction; upper/interior/lower targets explicit. Lower clamp uses an isolated arithmetic state, not a reachable-state claim.
//# When receiving a new ACK in congestion avoidance, if CUBIC is not in
//# the Reno-friendly region and _cwnd_ is less than _W_max_, then CUBIC
//# is in the concave region.  In this region, _cwnd_ MUST be incremented
//# by
//#
//# target - cwnd
//# ─────────────
//# cwnd
//#
//# for each received new ACK, where _target_ is calculated as described
//# in Section 4.2.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.5
//= type=test
//= reason=Concave, equality/convex and larger-cwnd convex vectors assert per-new-ACK increment and retained fraction; upper/interior/lower targets explicit. Lower clamp uses an isolated arithmetic state, not a reachable-state claim.
//# In this region, _cwnd_ MUST be
//# incremented by
//#
//# target - cwnd
//# ─────────────
//# cwnd
//#
//# for each received new ACK, where _target_ is calculated as described
//# in Section 4.2.
fn concave_convex_equality_and_target_bounds() {
    for (cwnd, elapsed, bound) in [
        (7000, 3_000_000, 1),   // concave, upper clamp
        (10_000, 3_000_000, 0), // equality belongs to convex
        (12_000, 4_000_000, 0), // convex, interior target
        (12_000, 5_000_000, 1), // convex, upper clamp
        (12_000, 0, -1),        // lower clamp (isolated arithmetic state)
    ] {
        let mut c = state(7000, 1000);
        c.elapsed = elapsed;
        c.rtt = 100_000;
        // Isolate the cubic branch, including the otherwise rarely reached
        // lower target clamp; this is not a reachable-state integration claim.
        c.w_est = 0;
        c.acked = 1;
        let current = u128::from(cwnd) * WINDOW_SCALE;
        let raw = c.window(c.seconds(elapsed + c.rtt), 1000);
        match bound {
            -1 => assert!(raw < current),
            1 => assert!(raw > current * 3 / 2),
            _ => assert!(raw > current && raw < current * 3 / 2),
        }
        let increment = (raw.clamp(current, current * 3 / 2) - current) * 1000 / u128::from(cwnd);
        let expected = cwnd + (increment / WINDOW_SCALE) as u32;
        assert_eq!(c.grow(cwnd, 1000), expected);
        assert_eq!(c.fraction, increment % WINDOW_SCALE);
        if bound == 1 {
            assert_eq!(expected, cwnd + 500);
        } else if bound == -1 {
            assert_eq!(expected, cwnd);
        }
        // Delayed and sub-MSS new ACKs use the same published cubic increment.
        for acked in [1000, 2000] {
            let mut delayed = state(7000, 1000);
            delayed.elapsed = elapsed;
            delayed.rtt = 100_000;
            delayed.w_est = 0;
            delayed.acked = acked;
            assert_eq!(delayed.grow(cwnd, 1000), expected);
        }
    }
}
