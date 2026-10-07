use super::*;

fn controller(recovery: RecoveryAlgorithm, mss: u32) -> Congestion {
    Congestion::new(mss, recovery, InitialWindow::Iw10, Seq(u32::MAX))
        .with_congestion(CongestionAlgorithm::Cubic, CallerTimebase::default())
}

#[test]
fn cubic_selection_is_independent_and_default_is_unchanged() {
    assert_eq!(CongestionAlgorithm::default(), CongestionAlgorithm::Reno);
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        let mut cubic = controller(recovery, 1000);
        let mut reno = Congestion::new(1000, recovery, InitialWindow::Iw10, Seq(u32::MAX));
        for c in [&mut cubic, &mut reno] {
            for _ in 0..2 {
                assert!(!c.on_duplicate_ack(Seq(1), 10_000, Seq(10_001), false));
            }
            assert!(c.on_duplicate_ack(Seq(1), 10_000, Seq(10_001), false));
        }
        assert_eq!((cubic.ssthresh, cubic.cwnd), (7000, 10_000));
        assert_eq!((reno.ssthresh, reno.cwnd), (5000, 8000));
        assert_eq!(
            cubic.on_ack(Seq(1001), 1000, 9000),
            recovery == RecoveryAlgorithm::NewReno
        );
        assert_eq!(
            cubic.cwnd,
            if recovery == RecoveryAlgorithm::Reno {
                7000
            } else {
                10_000
            }
        );
        // No CUBIC-only recovery exit override: NewReno's option (1) cap stays.
        assert!(!cubic.on_ack(Seq(10_001), 9000, 0));
        assert_eq!(
            cubic.cwnd,
            if recovery == RecoveryAlgorithm::Reno {
                7000
            } else {
                2000
            }
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=CUBIC ECN/TLP/loss beta thresholds, wrap, shared epoch guards and one-MSS/repeated-head timeout values asserted for both recovery selectors.
//# *  _ssthresh_: Current slow start threshold in segments.
//= https://www.rfc-editor.org/rfc/rfc9438#section-3.1
//= type=test
//= reason=CUBIC ECN/TLP/loss beta thresholds, wrap, shared epoch guards and one-MSS/repeated-head timeout values asserted for both recovery selectors.
//# After a window reduction in response to a congestion event detected
//# by duplicate acknowledgments (ACKs), Explicit Congestion
//# Notification-Echo (ECN-Echo (ECE)) ACKs [RFC3168], RACK-TLP for TCP
//# [RFC8985], or QUIC loss detection [RFC9002], CUBIC remembers the
//# congestion window size at which it received the congestion event and
//# performs a multiplicative decrease of the congestion window.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.8
//= type=test
//= reason=CUBIC ECN/TLP/loss beta thresholds, wrap, shared epoch guards and one-MSS/repeated-head timeout values asserted for both recovery selectors.
//# In the case of a timeout, CUBIC follows Reno to reduce _cwnd_
//# [RFC5681] but sets _ssthresh_ using β__cubic_ (same as in
//# Section 4.6) in a way that is different from Reno TCP [RFC5681].
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=CUBIC ECN/TLP/loss beta thresholds, wrap, shared epoch guards and one-MSS/repeated-head timeout values asserted for both recovery selectors.
//# The parameter β__cubic_ SHOULD be set to 0.7, which is different from
//# the multiplicative decrease factor used in [RFC5681] (and [RFC6675])
//# during fast recovery.
fn cubic_ecn_loss_tlp_and_rto_share_existing_epoch_guards() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for base in [Seq(1), Seq(u32::MAX - 4999)] {
            let end = base.wrapping_add(10_000);
            let mut c = controller(recovery, 1000);
            assert!(c.on_ecn(base, 10_000, end));
            assert_eq!((c.cwnd, c.ssthresh), (7000, 7000));
            assert!(!c.on_ecn(end, 7000, end));
            // Real loss still enters recovery but shares the ECN reduction.
            assert!(c.on_sack_recovery(base, 7000, end));
            assert_eq!(c.ssthresh, 7000);
            c.on_timeout(7000, end);
            assert_eq!((c.cwnd, c.ssthresh), (1000, 7000));
            c.on_timeout(3000, end);
            assert_eq!(c.ssthresh, 7000);

            let mut c = controller(recovery, 1000);
            assert!(c.on_tlp_repair(base, 10_000, end));
            assert_eq!((c.cwnd, c.ssthresh), (7000, 7000));
            assert!(!c.on_tlp_repair(base, 10_000, end));
            assert!(c.on_sack_recovery(base, 10_000, end));
            assert_eq!(c.ssthresh, 7000);
            c.on_retransmit(base.wrapping_add(1000));
            c.on_timeout(10_000, end);
            assert_eq!((c.cwnd, c.ssthresh), (1000, 4900));
            c.on_timeout(2000, end);
            assert_eq!(c.ssthresh, 4900);

            let mut c = controller(recovery, 1000);
            c.on_timeout(10_000, end);
            assert_eq!((c.cwnd, c.ssthresh), (1000, 7000));
            c.on_timeout(2000, end);
            assert_eq!(c.ssthresh, 7000);
            c.on_ack(end, 10_000, 0);
            c.on_timeout(20_000, end.wrapping_add(20_000));
            assert_eq!((c.cwnd, c.ssthresh), (1000, 14_000));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Successive distinct ECE flights reduce to one-MSS cwnd with two-MSS threshold and no ECE ACK growth.
//# Note that CUBIC MUST continue to reduce _cwnd_ in response to
//# congestion events detected by ECN-Echo ACKs until it reaches a value
//# of 1 SMSS.
fn cubic_ecn_one_mss_floor_no_ece_growth_and_idle_restart() {
    let mut c = controller(RecoveryAlgorithm::NewReno, 1000);
    let mut ack = Seq(1);
    let mut flight = 10_000;
    for _ in 0..10 {
        let end = ack.wrapping_add(flight);
        c.on_data_sent(0, flight, end, false);
        assert!(c.on_ecn(ack, flight, end));
        assert!(c.cwnd >= 1000 && c.ssthresh >= 2000);
        let before = c.cwnd;
        c.prepare_ack(1, Some(1), end, flight, MAX_WINDOW);
        c.on_ack_with_ecn(end, flight, 0, true);
        assert_eq!(c.cwnd, before);
        ack = end.wrapping_add(1);
        flight = c.cwnd;
    }
    assert_eq!((c.cwnd, c.ssthresh), (1000, 2000));
    c.restart_after_idle();
    assert_eq!(c.cwnd, 1000);
}

#[test]
fn cubic_mss_byte_bounds_and_growth_protection() {
    let mut c = controller(RecoveryAlgorithm::NewReno, 1000);
    c.on_timeout(10_000, Seq(10_001));
    c.set_mss(500);
    assert_eq!((c.cwnd, c.ssthresh), (500, 3500));
    c.set_mss(1000);
    assert_eq!((c.cwnd, c.ssthresh), (1000, 3500));
    c.prepare_ack(100, Some(100), Seq(1001), 1000, MAX_WINDOW);
    c.on_ack(Seq(1001), 1000, 0);
    assert_eq!(c.cwnd, 1000); // No committed output validating a full window.
    c.on_data_sent(200, 1000, Seq(2001), false);
    c.prepare_ack(300, Some(100), Seq(2001), 1000, MAX_WINDOW);
    c.on_ack(Seq(2001), 1000, 0);
    assert_eq!(c.cwnd, 2000);
    c.restart_after_idle();
    assert_eq!(c.cwnd, 2000); // Restart never increases the reduced window.
    for mss in [1, 1000, u32::MAX] {
        let mut c = controller(RecoveryAlgorithm::Reno, mss);
        c.on_data_sent(u64::MAX - 1, u32::MAX, Seq(u32::MAX), false);
        c.prepare_ack(
            u64::MAX,
            Some(u64::MAX),
            Seq(u32::MAX),
            u32::MAX,
            MAX_WINDOW,
        );
        c.on_ack(Seq(u32::MAX), u32::MAX, 0);
        c.on_timeout(u32::MAX, Seq(0));
        c.set_mss(u32::MAX);
        assert_eq!((c.cwnd, c.ssthresh), (MAX_WINDOW, MAX_WINDOW));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.10
//= type=test
//= reason=Lossless controller startup completes CSS then remains CA at cwnd=ssthresh; next full-flight ACK does not restart SS.
//# When CUBIC uses HyStart++ [RFC9406], it may exit the first slow start
//# without incurring any packet loss and thus _W_max_ is undefined.  In
//# this special case, CUBIC sets _cwnd_prior = cwnd_ and switches to
//# congestion avoidance.  It then increases its congestion window size
//# using Figure 1, where _t_ is the elapsed time since the beginning of
//# the current congestion avoidance stage, _K_ is set to 0, and _W_max_
//# is set to the congestion window size at the beginning of the current
//# congestion avoidance stage.
fn hystart_exit_is_authoritative_and_congestion_disables_initial_startup() {
    let mut c = controller(RecoveryAlgorithm::Reno, 1000);
    let mut base = Seq(u32::MAX - 4000);
    for round in 0..6 {
        let end = base.wrapping_add(10_000);
        c.on_data_sent(round * 200_000, c.cwnd(), end, false);
        for n in 1..=10 {
            let ack = base.wrapping_add(n * 1000);
            c.prepare_ack(
                round * 200_000 + 100_000,
                Some(100_000),
                ack,
                1000,
                MAX_WINDOW,
            );
            c.prepare_startup_ack(StartupAck {
                rtt: Some(if round == 0 { 100_000 } else { 113_000 }),
                snd_nxt: end,
                paced: false,
            });
            c.on_ack(ack, 1000, (10 - n) * 1000);
        }
        base = end;
    }
    assert!(c.hystart.is_none());
    assert!(c.congestion_avoidance);
    assert_eq!(c.cwnd, c.ssthresh);
    let before = c.cwnd;
    c.on_data_sent(1_300_000, before, base.wrapping_add(before), false);
    c.prepare_ack(
        1_400_000,
        Some(100_000),
        base.wrapping_add(1000),
        1000,
        MAX_WINDOW,
    );
    c.on_ack(base.wrapping_add(1000), 1000, before - 1000);
    assert!(c.cwnd < before + 1000); // Equality did not restart SS.

    for ecn in [false, true] {
        let mut c = controller(RecoveryAlgorithm::Reno, 1000);
        if ecn {
            c.on_ecn(Seq(1), 10_000, Seq(10_001));
            assert_eq!((c.cwnd, c.ssthresh), (7000, 7000));
            assert!(c.congestion_avoidance);
        } else {
            c.on_timeout(10_000, Seq(10_001));
            assert_eq!((c.cwnd, c.ssthresh), (1000, 7000));
            assert!(!c.congestion_avoidance); // Standard SS after RTO.
        }
        assert!(c.hystart.is_none());
        c.restart_after_idle();
        assert!(c.hystart.is_none());
    }
    let c = controller(RecoveryAlgorithm::Reno, 1000).with_cubic_hystart(false);
    assert!(c.hystart.is_none());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.8
//= type=test
//= reason=Controller ACKs traverse post-RTO standard SS including equality; first CA ACK initializes K=0,W_max=W_est origin8000 and uses prior-cwnd alpha9/17.
//# During the first congestion avoidance stage after a timeout, CUBIC
//# increases its congestion window size using Figure 1, where _t_ is the
//# elapsed time since the beginning of the current congestion avoidance
//# stage, _K_ is set to 0, and _W_max_ is set to the congestion window
//# size at the beginning of the current congestion avoidance stage.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.8
//= type=test
//= reason=Controller ACKs traverse post-RTO standard SS including equality; first CA ACK initializes K=0,W_max=W_est origin8000 and uses prior-cwnd alpha9/17.
//# In
//# addition, for the Reno-friendly region, _W_est_ SHOULD be set to the
//# congestion window size at the beginning of the current congestion
//# avoidance stage.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.10
//= type=test
//= reason=Controller ACKs traverse post-RTO standard SS including equality; first CA ACK initializes K=0,W_max=W_est origin8000 and uses prior-cwnd alpha9/17.
//# When _cwnd_ is no more than _ssthresh_, CUBIC MUST employ a slow
//# start algorithm.
fn first_ca_ack_after_timeout_uses_standard_ss_epoch_origin() {
    let mut c = controller(RecoveryAlgorithm::Reno, 1000);
    c.on_timeout(10_000, Seq(10_000));
    assert_eq!((c.cwnd, c.ssthresh), (1000, 7000));
    let mut base = Seq(10_001);
    for n in 1..=7 {
        let before = c.cwnd;
        let end = base.wrapping_add(before);
        c.on_data_sent(n * 200_000, before, end, false);
        c.prepare_ack(
            n * 200_000 + 100_000,
            Some(100_000),
            end,
            before,
            MAX_WINDOW,
        );
        c.on_ack(end, before, 0);
        assert_eq!(c.cwnd, before + 1000); // Standard SS, including equality.
        assert!(c.hystart.is_none());
        base = end;
    }
    assert_eq!(c.cwnd, 8000);
    c.on_data_sent(1_600_000, 8000, base.wrapping_add(8000), false);
    c.prepare_ack(
        1_700_000,
        Some(100_000),
        base.wrapping_add(1000),
        1000,
        MAX_WINDOW,
    );
    c.on_ack(base.wrapping_add(1000), 1000, 7000);
    assert_eq!(c.cwnd, 8066); // W_est starts at 8000; alpha=9/17 below prior10k.
    let state = alloc::format!("{:?}", c.cubic.as_ref().unwrap());
    for field in ["w_max: 8000,", "k: 0,", "epoch: true,", "elapsed: 0,"] {
        assert!(state.contains(field), "{state}");
    }
}

#[test]
fn partial_ack_underfill_freezes_clock_and_refill_resumes_it() {
    for recovery in [RecoveryAlgorithm::Reno, RecoveryAlgorithm::NewReno] {
        for scale in [1, 1000] {
            for suffix in [0, 500] {
                let mut c = Congestion::new(1000, recovery, InitialWindow::Iw10, Seq(u32::MAX))
                    .with_congestion(
                        CongestionAlgorithm::Cubic,
                        CallerTimebase {
                            units_per_second: 1_000_000 * scale,
                            ..CallerTimebase::default()
                        },
                    );
                assert!(c.on_ecn(Seq(0), 10_000, Seq(10_000)));
                c.on_data_sent(0, 7000, Seq(7000), false);
                c.prepare_ack(
                    100_000 * scale,
                    Some(100_000 * scale),
                    Seq(1000),
                    1000,
                    MAX_WINDOW,
                );
                c.on_ack(Seq(1000), 1000, 6000);
                assert_eq!(c.cwnd(), 7075);
                if suffix != 0 {
                    c.on_data_sent(600_000 * scale, 6000 + suffix, Seq(7000 + suffix), false);
                }
                c.prepare_ack(
                    700_000 * scale,
                    Some(100_000 * scale),
                    Seq(2000),
                    1000,
                    MAX_WINDOW,
                );
                assert_eq!(c.cubic.as_ref().unwrap().slow_start_acked(), 1000);
                c.on_ack(Seq(2000), 1000, 5000 + suffix);
                assert_eq!(c.cwnd(), 7150);
                let state = alloc::format!("{:?}", c.cubic.as_ref().unwrap());
                assert!(state.contains("elapsed: 0,"), "{state}");
                c.prepare_ack(
                    800_000 * scale,
                    Some(100_000 * scale),
                    Seq(7000 + suffix),
                    5000 + suffix,
                    MAX_WINDOW,
                );
                assert_eq!(c.cubic.as_ref().unwrap().slow_start_acked(), 5000);
                c.on_ack(Seq(7000 + suffix), 5000 + suffix, 0);
                assert_eq!(c.cwnd(), 7520);
                c.on_data_sent(
                    900_000 * scale,
                    c.cwnd(),
                    Seq(7000 + suffix + c.cwnd()),
                    false,
                );
                c.prepare_ack(
                    1_000_000 * scale,
                    Some(100_000 * scale),
                    Seq(8000 + suffix),
                    1000,
                    MAX_WINDOW,
                );
                c.on_ack(Seq(8000 + suffix), 1000, 6520);
                let state = alloc::format!("{:?}", c.cubic.as_ref().unwrap());
                assert!(
                    state.contains(&alloc::format!("elapsed: {},", 100_000 * scale)),
                    "{state}"
                );
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.2
//= type=test
//= reason=Real encoded/parsed TCP flights, partial ACKs and no-output/delayed-short-suffix gaps retain exact historical ACK growth7075/7150/7520 instead of aging the cubic curve; sequence wrap included. Controller test separately asserts frozen elapsed and full-flight refill resumption in us/ns.
//# The elapsed time _t_ in Figure 1 MUST NOT include periods during
//# which _cwnd_ has not been updated due to application-limited behavior
//# (see Section 5.8).
fn wire_partial_ack_gap_and_delayed_suffix_keep_historical_growth() {
    use crate::{ConnectionConfig, State, Tuple, connection::Connection, wire};

    for iss in [0, u32::MAX - 12_000] {
        for suffix in [0, 500] {
            let tuple = Tuple {
                local: "192.0.2.1:1000".parse().unwrap(),
                remote: "192.0.2.2:2000".parse().unwrap(),
            };
            let outgoing = wire::IpMetadata {
                source: tuple.local.ip(),
                destination: tuple.remote.ip(),
            };
            let incoming = wire::IpMetadata {
                source: tuple.remote.ip(),
                destination: tuple.local.ip(),
            };
            let mut a = Connection::active(
                tuple,
                ConnectionConfig {
                    congestion_algorithm: CongestionAlgorithm::Cubic,
                    initial_window: InitialWindow::Iw10,
                    mss: 1000,
                    send_capacity: 32_000,
                    receive_capacity: 32_000,
                    ecn: true,
                    nagle: false,
                    timestamps: false,
                    prr_pacing: false,
                    ..ConnectionConfig::default()
                },
                iss,
                0,
            )
            .unwrap();
            let input = |a: &mut Connection, now, ack: Seq, flags| {
                let mut bytes = [0; 64];
                let len = wire::encode(
                    incoming,
                    wire::Header {
                        source_port: tuple.remote.port(),
                        destination_port: tuple.local.port(),
                        sequence: if flags & wire::SYN != 0 { 901 } else { 902 },
                        acknowledgment: ack.0,
                        flags,
                        window: 32_000,
                        urgent_pointer: 0,
                    },
                    if flags & wire::SYN != 0 {
                        &[2, 4, 3, 232]
                    } else {
                        &[]
                    },
                    &[],
                    &mut bytes,
                )
                .unwrap();
                a.input(now, &wire::parse(incoming, &bytes[..len]).unwrap())
                    .unwrap();
            };
            let mut out = [0; 1500];
            a.transmit(0, &mut out).unwrap().unwrap();
            input(
                &mut a,
                20,
                Seq(iss).wrapping_add(1),
                wire::SYN | wire::ACK | wire::ECE,
            );
            assert_eq!(a.state(), State::Established);
            a.transmit(30, &mut out).unwrap().unwrap();
            a.write(&[0x55; 10_000]).unwrap();
            for n in 0..10 {
                let len = a.transmit(1000, &mut out).unwrap().unwrap();
                let segment = wire::parse(outgoing, &out[..len]).unwrap();
                assert_eq!(segment.payload.len(), 1000);
                assert_eq!(segment.header.sequence, iss.wrapping_add(1 + n * 1000));
            }
            let base = Seq(iss).wrapping_add(10_001);
            input(&mut a, 50_000, base, wire::ACK | wire::ECE);
            assert_eq!(a.transport_info().cwnd, 7000);
            a.write(&[0x66; 7000]).unwrap();
            for n in 0..7 {
                let len = a.transmit(100_000, &mut out).unwrap().unwrap();
                let segment = wire::parse(outgoing, &out[..len]).unwrap();
                assert_eq!(segment.payload.len(), 1000);
                assert_eq!(segment.header.sequence, base.wrapping_add(n * 1000).0);
            }
            input(&mut a, 200_000, base.wrapping_add(1000), wire::ACK);
            assert_eq!(a.transport_info().cwnd, 7075);
            // No output at all in one case; delayed application output in the other.
            if suffix != 0 {
                a.write(&[0x77; 500]).unwrap();
                let len = a.transmit(500_000, &mut out).unwrap().unwrap();
                let segment = wire::parse(outgoing, &out[..len]).unwrap();
                assert_eq!(segment.header.sequence, base.wrapping_add(7000).0);
                assert_eq!(segment.payload.len(), 500);
            }
            input(&mut a, 600_000, base.wrapping_add(2000), wire::ACK);
            assert_eq!(a.transport_info().cwnd, 7150);
            input(&mut a, 700_000, base.wrapping_add(7000 + suffix), wire::ACK);
            assert_eq!(a.transport_info().cwnd, 7520);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.1.2
//= type=test
//= reason=Small-flight loss/ECE vectors assert two/one-SMSS byte cwnd floors, two-SMSS threshold and saved pre-event cwnd/W_max; complements actual ten-MSS loss/PRR wire response.
//# *  _cwnd_: Current congestion window in segments.
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Small-flight loss/ECE vectors assert two/one-SMSS byte cwnd floors, two-SMSS threshold and saved pre-event cwnd/W_max; complements actual ten-MSS loss/PRR wire response.
//# ssthresh =  flight_size * β      new  ssthresh
//# cubic
//# cwnd      = cwnd                 save  cwnd
//# prior
//# ⎧max(ssthresh, 2)    reduction on loss, cwnd >= 2 SMSS
//# cwnd =      ⎨max(ssthresh, 1)    reduction on ECE, cwnd >= 1 SMSS
//# ⎩
//# ssthresh =  max(ssthresh, 2)     ssthresh >= 2 SMSS
//#
//# Figure 5
fn cubic_loss_and_ecn_floors_save_pre_event_window() {
    for ecn in [false, true] {
        let mut c = controller(RecoveryAlgorithm::Reno, 1000);
        if ecn {
            assert!(c.on_ecn(Seq(1), 500, Seq(501)));
        } else {
            assert!(c.on_sack_recovery(Seq(1), 500, Seq(501)));
        }
        assert_eq!(c.ssthresh, 2000);
        assert_eq!(c.cwnd, if ecn { 1000 } else { 2000 });
        let state = alloc::format!("{:?}", c.cubic.as_ref().unwrap());
        assert!(state.contains("cwnd_prior: 10000,"), "{state}");
        assert!(state.contains("w_max: 10000,"), "{state}");
    }
}
