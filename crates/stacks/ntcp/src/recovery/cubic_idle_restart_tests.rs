// SPDX-License-Identifier: MIT
use super::*;

// Controller vectors use only normal sent/ACK/ECN APIs, never assign cwnd or phase.
fn ca(recovery: RecoveryAlgorithm, base: Seq) -> (Congestion, Seq) {
    let mut c = controller(recovery, 1000);
    let first = base.wrapping_add(10000);
    c.on_data_sent(0, 10000, first, false);
    assert!(c.on_ecn(base, 10000, first));
    c.prepare_ack(100000, Some(100000), first, 10000, MAX_WINDOW);
    c.on_ack_with_ecn(first, 10000, 0, true);
    let flight = c.cwnd();
    let next = first.wrapping_add(flight);
    c.on_data_sent(200000, flight, next, false);
    c.prepare_ack(300000, Some(100000), next, flight, MAX_WINDOW);
    c.on_ack(next, flight, 0);
    assert!(c.cwnd() > c.ssthresh && c.congestion_avoidance);
    assert!(c.hystart.is_none());
    (c, next)
}

//= https://www.rfc-editor.org/rfc/rfc9438#section-4.10
//= type=test
//= reason=Real controller sends/ACKs/ECN reach CA; actual idle decreases below/equal/above threshold select standard SS only where required, including a4k final cap below IW10, wrap and both recovery selectors. Separate vectors protect active loss, ECN PRR, pending probe response and unchanged windows.
//# When _cwnd_ is no more than _ssthresh_, CUBIC MUST employ a slow
//# start algorithm.
#[test]
fn idle_final_window_selects_ss_below_and_at_threshold_only_after_actual_drop() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for base in [Seq(1), Seq(u32::MAX - 20000)] {
            for relation in [-1, 0, 1] {
                let (mut c, ack) = ca(recovery, base);
                let threshold = c.ssthresh;
                let before = c.cwnd();
                // 4k is a real selected RFC3390 fallback cap, less than IW10.
                let window = match relation {
                    -1 => 4000,
                    0 => threshold,
                    _ => threshold + 1,
                };
                assert!(window < before && before < c.initial_window());
                let markers = (c.recover, c.initial_recover, c.ecn_end, c.tlp_reduction_end);
                c.restart_after_idle(window);
                assert_eq!(c.cwnd(), window);
                assert_eq!(c.ssthresh, threshold);
                assert_eq!(c.congestion_avoidance, relation > 0);
                assert!(c.hystart.is_none());
                assert_eq!(
                    (c.recover, c.initial_recover, c.ecn_end, c.tlp_reduction_end),
                    markers
                );
                let end = ack.wrapping_add(window);
                c.on_data_sent(400000, window, end, false);
                let next = ack.wrapping_add(2000);
                c.prepare_ack(500000, Some(100000), next, 2000, MAX_WINDOW);
                c.on_ack(next, 2000, window - 2000);
                if relation <= 0 {
                    assert_eq!(c.cwnd(), window + 1000);
                } else {
                    assert!(c.cwnd() <= window + 500);
                }
            }
        }
    }
}

#[test]
fn unchanged_window_and_generic_admission_limit_do_not_reset_ca() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        let (mut c, _) = ca(recovery, Seq(1));
        let before = c.cwnd();
        c.restart_after_idle(c.initial_window());
        assert_eq!(c.cwnd(), before);
        assert!(c.congestion_avoidance && c.hystart.is_none());
        c.limit_restart(4000);
        assert!(c.cwnd() < c.ssthresh);
        assert!(c.congestion_avoidance);
    }
}

#[test]
fn active_loss_and_ecn_prr_keep_recovery_phase_guards() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for ecn in [false, true] {
            let (mut c, ack) = ca(recovery, Seq(1));
            let flight = c.cwnd();
            let end = ack.wrapping_add(flight);
            c.on_data_sent(400000, flight, end, false);
            if ecn {
                assert!(c.on_ecn(ack, flight, end));
                assert!(c.start_ecn_prr(end, flight, c.cwnd(), 1000));
            } else {
                assert!(c.on_sack_recovery(ack, flight, end));
            }
            let protected = (c.in_recovery(), c.ecn_prr_end(), c.recover, c.ssthresh);
            let admission = c.cwnd();
            c.restart_after_idle(1000);
            assert_eq!(c.unsuppressed_cwnd(), 1000);
            assert_eq!(c.cwnd(), if ecn { admission } else { 1000 });
            assert!(c.congestion_avoidance);
            assert_eq!(
                (c.in_recovery(), c.ecn_prr_end(), c.recover, c.ssthresh),
                protected
            );
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
//= type=test
//= reason=Post-RTO idle does not recreate HyStart; a full-window acknowledged flight grows by one MSS using standard SS. Real-wire completed-HyStart idle regression separately verifies the same restart growth.
//# An implementation SHOULD use HyStart++ only for the initial slow
//# start (when the ssthresh is at its initial value of arbitrarily high
//# per [RFC5681]) and fall back to using standard slow start for the
//# remainder of the connection lifetime.
#[test]
fn idle_after_timeout_keeps_standard_ss_without_new_hystart() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        let mut c = controller(recovery, 1000);
        c.on_timeout(10000, Seq(10001));
        assert!(c.hystart.is_none() && !c.congestion_avoidance);
        c.restart_after_idle(c.initial_window());
        assert_eq!(c.cwnd(), 1000);
        assert!(c.hystart.is_none() && !c.congestion_avoidance);
        c.on_data_sent(200000, 1000, Seq(11001), false);
        c.prepare_ack(300000, Some(100000), Seq(11001), 1000, MAX_WINDOW);
        c.on_ack(Seq(11001), 1000, 0);
        assert_eq!(c.cwnd(), 2000);
    }
}

#[test]
fn pending_isolated_probe_keeps_ca_after_sack_recovery_exits() {
    let (mut c, ack) = ca(RecoveryAlgorithm::NewReno, Seq(1));
    let flight = c.cwnd();
    let end = ack.wrapping_add(flight);
    c.on_data_sent(400_000, flight, end, false);
    assert!(c.on_sack_recovery_with_probe(ack, flight, end, Some(ack)));
    c.on_ack(end, flight, 0);
    assert!(!c.in_recovery());
    assert_eq!(c.pending_probe_response(), Some(ack));
    let admission = c.cwnd();
    c.restart_after_idle(1000);
    assert_eq!(c.unsuppressed_cwnd(), 1000);
    assert_eq!(c.cwnd(), admission);
    assert!(c.congestion_avoidance);
    assert_eq!(c.pending_probe_response(), Some(ack));
}

#[test]
fn reno_idle_decrease_reenters_ss_after_completed_loss_recovery() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        let mut c = Congestion::new(1000, recovery, InitialWindow::Iw10, Seq(u32::MAX));
        assert!(c.on_sack_recovery(Seq(1), 10_000, Seq(10_001)));
        c.on_ack(Seq(10_001), 10_000, 0);
        assert!(!c.in_recovery() && c.congestion_avoidance);
        let threshold = c.ssthresh();
        let mut ack = Seq(10_001);
        let mut now = 100_000;
        while c.cwnd() <= threshold {
            let flight = c.cwnd();
            let end = ack.wrapping_add(flight);
            c.on_data_sent(now, flight, end, false);
            c.prepare_ack(now + 100_000, Some(100_000), end, flight, MAX_WINDOW);
            c.on_ack(end, flight, 0);
            ack = end;
            now += 200_000;
        }
        assert_eq!(c.cwnd(), 6000);
        c.restart_after_idle(4000);
        assert_eq!(c.cwnd(), 4000);
        assert!(!c.congestion_avoidance);
        c.on_data_sent(now, 4000, ack.wrapping_add(4000), false);
        c.on_ack(ack.wrapping_add(2000), 2000, 2000);
        assert_eq!(c.cwnd(), 5000);
        assert_eq!(c.ssthresh(), threshold);
    }
}
