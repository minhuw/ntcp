use super::*;

fn sender(sack: bool, rack: bool, iss: u32, bytes: usize) -> Connection {
    let mut cfg = config(32_000, 1000);
    cfg.ecn = true;
    cfg.nagle = false;
    cfg.initial_window = InitialWindow::Iw10;
    cfg.congestion_algorithm = CongestionAlgorithm::Cubic;
    cfg.sack = sack;
    cfg.rack = rack;
    cfg.prr = true;
    let (mut a, _) = pair(cfg, iss);
    a.write(&vec![1; bytes]).unwrap();
    for _ in 0..bytes.div_ceil(1000) {
        packet(&mut a, 40);
    }
    a
}

fn ack(a: &mut Connection, now: u64, edge: Seq, ece: bool, blocks: &[(u32, u32)]) {
    inject_sack(
        a,
        now,
        a.receive.next(),
        edge,
        ACK | if ece { ECE } else { 0 },
        32_000,
        &[],
        blocks,
    );
}

#[test]
fn cubic_ecn_prr_safe_entry_output_multiple_acks_and_handoff() {
    for (sack, rack) in [(false, false), (true, false), (true, true)] {
        for iss in [0, u32::MAX - 1999] {
            let mut a = sender(sack, rack, iss, 4000);
            let base = a.snd_una;
            let end = a.snd_nxt;
            ack(&mut a, 50, base.wrapping_add(1000), true, &[]);
            assert_eq!(a.congestion.ssthresh(), 7000);
            assert_eq!(a.congestion.unsuppressed_cwnd(), 7000);
            assert_eq!(a.congestion.cwnd(), 5000);
            assert_eq!(a.congestion.ecn_prr_end(), Some(end));
            assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 0));
            assert_eq!(a.prr.unwrap().credit(), 2000);
            assert!(!a.retx_pending && !a.congestion.in_recovery());
            assert_eq!(a.rack.counts().lost, 0);
            // Failed output consumes neither credit nor the first-fresh CWR.
            a.write(&[2; 8000]).unwrap();
            assert_eq!(a.transmit(51, &mut [0; 20]), Err(Error::OutputTooSmall));
            assert_eq!(a.prr.unwrap().credit(), 2000);
            for i in 0..2 {
                let bytes = packet(&mut a, 52);
                let seg = wire::parse(ip(a.tuple()), &bytes).unwrap();
                assert_eq!(seg.header.sequence, end.wrapping_add(i * 1000).0);
                assert_eq!(seg.payload.len(), 1000);
                assert_eq!(seg.header.flags & CWR != 0, i == 0);
            }
            assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 2000));
            assert!(a.transmit(52, &mut [0; 1500]).unwrap().is_none());
            assert_eq!(a.congestion.ecn_prr_end(), Some(end)); // CWR output is not completion.
            ack(&mut a, 60, base.wrapping_add(2000), true, &[]);
            assert_eq!(a.congestion.unsuppressed_cwnd(), 7000); // Repeated ECE does not re-reduce.
            assert_eq!(a.prr.unwrap().counters(), (4000, 2000, 2000));
            assert_eq!(a.prr.unwrap().credit(), 2000);
            assert_eq!(a.congestion.cwnd(), 6000);
            // A non-ECE ACK inside the episode must not grow the logical target.
            ack(&mut a, 70, base.wrapping_add(3000), false, &[]);
            assert_eq!(a.congestion.unsuppressed_cwnd(), 7000);
            assert_eq!(a.prr.unwrap().counters(), (4000, 3000, 2000));
            let before = a.prr.unwrap().counters();
            ack(&mut a, 80, end, true, &[]);
            assert!(a.prr.is_none());
            assert_eq!(a.congestion.ecn_prr_end(), None);
            assert_eq!(a.prr_exit_trace.unwrap().counters(), before);
            assert_eq!(a.congestion.cwnd(), 7000);
            // Ordinary output uses the restored logical window, not stale credit.
            for _ in 0..5 {
                packet(&mut a, 81);
            }
            assert_eq!(a.data_flight(), 7000);
            assert!(a.transmit(81, &mut [0; 1500]).unwrap().is_none());
            // A new event beyond the old boundary uses 7000, not its former 6000 admission.
            ack(&mut a, 90, end.wrapping_add(1000), true, &[]);
            assert_eq!(a.congestion.ssthresh(), 4900);
            assert_eq!(a.congestion.unsuppressed_cwnd(), 4900);
        }
    }
}

#[test]
fn cubic_ecn_prr_signed_sack_delivery_replay_and_loss_takeover() {
    for rack in [false, true] {
        for iss in [0, u32::MAX - 1999] {
            let mut a = sender(true, rack, iss, 4000);
            let base = a.snd_una;
            let end = a.snd_nxt;
            // Prior SACK evidence is excluded from RecoverFS, not replayed on entry.
            ack(
                &mut a,
                50,
                base,
                false,
                &[(base.wrapping_add(3000).0, end.0)],
            );
            assert!(a.prr.is_none());
            ack(
                &mut a,
                51,
                base.wrapping_add(1000),
                true,
                &[(base.wrapping_add(2000).0, end.0)],
            );
            assert_eq!(a.prr.unwrap().counters(), (3000, 2000, 0));
            let before = a.prr.unwrap().counters();
            let credit = a.prr.unwrap().credit();
            ack(
                &mut a,
                52,
                base.wrapping_add(1000),
                true,
                &[(base.wrapping_add(2000).0, end.0)],
            );
            assert_eq!(a.prr.unwrap().counters(), before);
            assert_eq!(a.prr.unwrap().credit(), credit);
            ack(&mut a, 53, base.wrapping_add(3000), false, &[]);
            assert_eq!(a.prr.unwrap().counters(), (3000, 3000, 0)); // Only unsacked hole is new.
            let before = a.prr.unwrap().counters();
            ack(&mut a, 54, end, true, &[]);
            assert_eq!(a.prr_exit_trace.unwrap().counters(), before);
            assert!(a.prr.is_none());
        }
    }
    for sack in [false, true] {
        let mut a = sender(sack, false, 0, 8000);
        let base = a.snd_una;
        ack(&mut a, 50, base.wrapping_add(1000), true, &[]);
        let blocks = [(base.wrapping_add(4000).0, base.wrapping_add(8000).0)];
        for _ in 0..3 {
            ack(
                &mut a,
                60,
                base.wrapping_add(1000),
                true,
                if sack { &blocks } else { &[] },
            );
        }
        assert!(a.congestion.in_recovery());
        assert_eq!(a.congestion.ecn_prr_end(), None);
        assert_eq!(a.congestion.ssthresh(), 7000); // Same original-flight reduction.
        let bytes = packet(&mut a, 61);
        let seg = wire::parse(ip(a.tuple()), &bytes).unwrap();
        assert_eq!(seg.header.sequence, base.wrapping_add(1000).0);
        assert_eq!(seg.header.flags & CWR, 0); // Retransmit does not consume pending CWR.
        assert!(a.ecn_cwr_pending);
        let before = a.prr.unwrap().counters();
        ack(&mut a, 62, base.wrapping_add(2000), true, &[]);
        assert_eq!(a.congestion.ssthresh(), 7000);
        assert_eq!(a.prr.unwrap().counters().0, before.0);
    }
}

#[test]
fn cubic_ecn_prr_small_flight_fin_and_cancellations() {
    for bytes in [1, 500, 1000] {
        let mut a = sender(true, true, u32::MAX - 200, bytes);
        let end = a.snd_nxt;
        ack(&mut a, 50, end, true, &[]);
        assert!(a.prr.is_none()); // Entry ACK also covers the bounded episode.
        assert_eq!((a.congestion.cwnd(), a.congestion.ssthresh()), (7000, 7000));
        assert!(a.ecn_cwr_pending);
    }
    for fin in [false, true] {
        let mut a = sender(true, true, 0, 4000);
        let base = a.snd_una;
        if fin {
            a.shutdown().unwrap();
            packet(&mut a, 41);
        }
        let end = a.snd_nxt;
        ack(&mut a, 50, base.wrapping_add(1000), true, &[]);
        assert_eq!(a.congestion.ecn_prr_end(), Some(end));
        if fin {
            ack(&mut a, 60, base.wrapping_add(4000), true, &[]);
            assert!(a.prr.is_some()); // FIN is part of the boundary, not delivered payload.
            let before = a.prr.unwrap().counters();
            ack(&mut a, 70, end, true, &[]);
            assert_eq!(a.prr_exit_trace.unwrap().counters(), before);
            assert!(a.prr.is_none());
            assert_eq!(a.state(), State::FinWait2);
        } else {
            let threshold = a.congestion.ssthresh();
            a.timeout(a.rto_deadline.unwrap()).unwrap();
            assert!(a.prr.is_none());
            assert_eq!(a.congestion.ecn_prr_end(), None);
            assert_eq!(a.congestion.cwnd(), 1000);
            assert_eq!(a.congestion.ssthresh(), threshold);
        }
    }
    let mut a = sender(true, true, 0, 4000);
    let edge = a.snd_una.wrapping_add(1000);
    ack(&mut a, 50, edge, true, &[]);
    let next = a.receive.next();
    inject(&mut a, 60, next, edge, ACK, 0, &[]);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.ecn_prr_end(), None);
    assert_eq!(a.congestion.cwnd(), 7000);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9438#section-4.6
//= type=test
//= reason=Real short-flight and receiver-limited ACKs do not grow the next ECN basis; an enlarged validated window is reduced by actual idle restart before its next ECN response. Complements Cubic clock/limited-end tests.
//# Implementations
//# that use _cwnd_ MUST use other measures to prevent _cwnd_ from
//# growing when the volume of bytes in flight is smaller than
//# _cwnd_.
fn cubic_ecn_prr_application_receiver_limits_and_idle_target() {
    // Neither short-flight ACKs nor receiver-limited full-flight ACKs validate
    // growth; elapsed wall time cannot inflate the next ECN target.
    for receiver_limited in [false, true] {
        let mut a = sender(true, true, 0, if receiver_limited { 10_000 } else { 1000 });
        let end = a.snd_nxt;
        let next = a.receive.next();
        inject(
            &mut a,
            100_000,
            next,
            end,
            ACK,
            if receiver_limited { 1000 } else { 32_000 },
            &[],
        );
        assert_eq!(a.congestion.cwnd(), 10_000);
        a.write(&[2; 1000]).unwrap();
        let idle = 100_000 + a.rto();
        packet(&mut a, idle);
        assert_eq!(a.congestion.cwnd(), 10_000);
        let end = a.snd_nxt;
        ack(&mut a, idle + 100, end, true, &[]);
        assert_eq!(a.congestion.cwnd(), 7000);
    }
    // Independently validate that an actually enlarged window is cut by idle
    // restart before it supplies a later ECN target.
    let mut a = sender(true, true, 0, 10_000);
    let end = a.snd_nxt;
    ack(&mut a, 100_000, end, false, &[]);
    assert!(a.congestion.cwnd() > 10_000);
    a.write(&[2; 1000]).unwrap();
    let idle = 100_000 + a.rto();
    packet(&mut a, idle);
    assert_eq!(a.congestion.cwnd(), 10_000);
    let end = a.snd_nxt;
    ack(&mut a, idle + 100, end, true, &[]);
    assert_eq!(a.congestion.cwnd(), 7000);
}

#[test]
fn cubic_ecn_prr_rack_timer_replaces_episode_without_ack_replay() {
    let mut a = sender(true, true, 0, 8000);
    let base = a.snd_una;
    ack(&mut a, 100_000, base.wrapping_add(1000), true, &[]);
    let end = a.congestion.ecn_prr_end();
    ack(
        &mut a,
        100_001,
        base.wrapping_add(1000),
        true,
        &[(base.wrapping_add(7000).0, base.wrapping_add(8000).0)],
    );
    assert_eq!(a.congestion.ecn_prr_end(), end);
    let deadline = a.rack.deadline.unwrap();
    a.timeout(deadline).unwrap();
    assert!(a.sack_recovery.is_some());
    assert_eq!(a.congestion.ecn_prr_end(), None);
    assert_eq!(a.congestion.ssthresh(), 7000);
    assert_eq!(a.prr.unwrap().counters(), (6000, 0, 0));
    assert_eq!(a.prr.unwrap().credit(), 0); // Timer is not another copy of the ACK.
    assert!(a.transmit(deadline, &mut [0; 1500]).unwrap().is_none());
}

#[test]
fn cubic_ecn_prr_loss_ending_ack_starts_new_logical_event() {
    for (sack, rollback) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut a = sender(sack, false, 0, 10_000);
        let base = a.snd_una;
        // Advancing original ACK clears NewReno's initial guard.
        ack(&mut a, 50, base.wrapping_add(1000), false, &[]);
        let end = a.snd_nxt;
        let blocks = [(base.wrapping_add(7000).0, end.0)];
        for _ in 0..3 {
            ack(
                &mut a,
                60,
                base.wrapping_add(1000),
                false,
                if sack { &blocks } else { &[] },
            );
        }
        let loss_target = a.congestion.ssthresh();
        assert!(a.congestion.in_recovery());
        a.write(&[2; 5000]).unwrap();
        // Deliver the repair, then send beyond the old loss boundary while still
        // in recovery. The next ECE ACK covers that boundary and starts ECN.
        packet(&mut a, 61);
        ack(&mut a, 70, base.wrapping_add(7000), false, &[]);
        for _ in 0..3 {
            packet(&mut a, 71);
        }
        assert!(after(a.snd_nxt, end.wrapping_add(1000)));
        let now = if rollback {
            pending_verification_rollback(&mut a, 500)
        } else {
            80
        };
        ack(&mut a, now, end.wrapping_add(1000), true, &[]);
        let target = (loss_target * 7 / 10) / if rollback { 2 } else { 1 };
        assert!(!a.congestion.in_recovery());
        assert!(a.congestion.ecn_prr_end().is_some());
        assert_eq!(a.congestion.ssthresh(), target);
        assert_eq!(a.congestion.unsuppressed_cwnd(), target);
        assert_eq!(a.prr.unwrap().counters().1, if sack { 1000 } else { 4000 });
        let end = a.snd_nxt;
        ack(&mut a, now + 1, end, true, &[]);
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.cwnd(), target);
    }
}

#[test]
fn cubic_ecn_prr_reserved_pacing_and_mss_preserve_logical_target() {
    let mut a = sender(true, true, 0, 4000);
    let base = a.snd_una;
    ack(&mut a, 100_000, base.wrapping_add(1000), true, &[]);
    a.config.prr_pacing = true;
    a.write(&[2; 4000]).unwrap();
    let mut bytes = [0; 1500];
    let n = a
        .transmit_selected(100_001, &mut bytes, true)
        .unwrap()
        .unwrap();
    let seg = wire::parse(ip(a.tuple()), &bytes[..n]).unwrap();
    assert_eq!(seg.header.sequence, base.wrapping_add(4000).0);
    assert_eq!(seg.payload.len(), 1000);
    let counters = a.prr.unwrap().counters();
    assert_eq!(counters, (4000, 1000, 1000));
    let mut departure = a.last_departure.unwrap();
    a.accept_reserved_output(100_002, &mut departure, 0, 500, false)
        .unwrap();
    a.accept_reserved_output(100_003, &mut departure, 500, 500, true)
        .unwrap();
    assert_eq!(a.prr.unwrap().counters(), counters); // No double charge at departure.
    assert_eq!(a.congestion.unsuppressed_cwnd(), 7000);
    let due = a.pacing_deadline.unwrap();
    assert!(a.transmit(due - 1, &mut bytes).unwrap().is_none());
    packet(&mut a, due);
    assert_eq!(a.prr.unwrap().credit(), 0);
    assert!(a.transmit(due, &mut bytes).unwrap().is_none());
    a.lower_mss(500).unwrap();
    assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 2000));
    assert_eq!(a.congestion.unsuppressed_cwnd(), 3500);
    assert_eq!(a.congestion.cwnd(), 2500);
    assert_eq!(a.congestion.ssthresh(), 3500);
    ack(&mut a, due + 1, base.wrapping_add(4000), true, &[]);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.cwnd(), 3500);
}

#[test]
fn cubic_ecn_prr_one_mss_partial_ack_pause_and_last_ack() {
    let mut a = sender(true, true, 0, 1000);
    let mut now = 50;
    while a.congestion.unsuppressed_cwnd() > 1000 {
        let end = a.snd_nxt;
        ack(&mut a, now, end, true, &[]);
        assert!(a.prr.is_none());
        a.write(&[2; 1000]).unwrap();
        now += 10;
        packet(&mut a, now);
        now += 10;
    }
    let base = a.snd_una;
    ack(&mut a, now, base.wrapping_add(500), true, &[]);
    assert_eq!(a.congestion.ssthresh(), 2000);
    assert_eq!(a.congestion.recovery_target(), 2000);
    assert_eq!(a.congestion.unsuppressed_cwnd(), 1000);
    assert_eq!(a.congestion.cwnd(), 1000);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.ecn_prr_end(), None);
    let pause = a.ecn_pause.unwrap();
    a.write(&[3; 1000]).unwrap();
    assert!(a.transmit(now, &mut [0; 1500]).unwrap().is_none());
    ack(&mut a, now + 1, base.wrapping_add(1000), true, &[]);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.cwnd(), 1000); // Completion must not restore ssthresh=2000.
    assert_eq!(a.ecn_pause, Some(pause));
    ack(&mut a, now + 2, base.wrapping_add(1000), true, &[]);
    assert_eq!(a.ecn_pause, Some(pause));
    assert!(a.transmit(pause - 1, &mut [0; 1500]).unwrap().is_none());
    a.timeout(pause).unwrap();
    assert_eq!(
        wire::parse(ip(a.tuple()), &packet(&mut a, pause))
            .unwrap()
            .payload
            .len(),
        1000
    );

    let mut a = sender(true, true, u32::MAX - 2000, 4000);
    let base = a.snd_una;
    let next = a.receive.next();
    inject(&mut a, 45, next, base, ACK | FIN, 32_000, &[]);
    assert_eq!(a.state(), State::CloseWait);
    a.shutdown().unwrap();
    packet(&mut a, 46);
    assert_eq!(a.state(), State::LastAck);
    let end = a.snd_nxt;
    ack(&mut a, 50, base.wrapping_add(1000), true, &[]);
    assert!(a.prr.is_some());
    ack(&mut a, 60, end, true, &[]);
    assert_eq!(a.state(), State::Closed);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.ecn_prr_end(), None);
}

#[test]
fn cubic_ecn_prr_scoreboard_fallback_cannot_recreate_episode() {
    for already_active in [false, true] {
        let mut a = sender(true, true, 0, 4000);
        let base = a.snd_una;
        if already_active {
            ack(&mut a, 50, base.wrapping_add(1000), true, &[]);
            assert!(a.prr.is_some());
        }
        a.scoreboard = Scoreboard::with_capacity(1).unwrap();
        ack(
            &mut a,
            60,
            base.wrapping_add(1000),
            true,
            &[
                (base.wrapping_add(2000).0, base.wrapping_add(2001).0),
                (base.wrapping_add(3000).0, base.wrapping_add(3001).0),
            ],
        );
        assert!(a.sack_fallback.is_some());
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.ecn_prr_end(), None);
        assert_eq!(a.congestion.cwnd(), 7000);
    }
}

// Seed the PMTU verifier through its probe/sent/ACK interface. The connection's
// next real ACK, not a test-side MSS setter, must expire the lossy observation.
fn pending_verification_rollback(a: &mut Connection, baseline_mss: u32) -> u64 {
    assert!(!a.timestamps);
    let headers = u32::from(a.ip_header_len) + 20;
    let mtu = a.mss as u32 + headers;
    let mut p = crate::pmtud::Pmtud::new(crate::PmtudConfig::new(mtu), mtu, true, 600_000_000);
    p.info.current_mtu = baseline_mss + headers;
    let start = Seq(a.snd_una.0.wrapping_sub(a.mss as u32));
    p.start_probe(start, a.mss as u32, 0, mtu);
    p.sent(start, a.snd_una, mtu, 20, false);
    p.ack(a.snd_una, 40, 1000, a.rto());
    assert_eq!(p.info.current_mtu, mtu);
    p.sent(a.snd_una, a.snd_nxt, mtu, 20, false);
    p.sent(a.snd_una, a.snd_nxt, mtu, 20, true);
    a.pmtud = Some(p);
    40 + 2 * a.rto()
}

#[test]
fn cubic_ecn_prr_entry_ack_pmtu_verification_rollback() {
    for ending in [false, true] {
        let mut a = sender(true, false, 0, 4000);
        let base = a.snd_una;
        let end = a.snd_nxt;
        let now = pending_verification_rollback(&mut a, 500);
        ack(
            &mut a,
            now,
            if ending { end } else { base.wrapping_add(1000) },
            true,
            &[],
        );
        assert_eq!(a.mss, 500);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 540);
        assert_eq!(a.congestion.ssthresh(), 3500);
        assert_eq!(a.congestion.unsuppressed_cwnd(), 3500);
        assert_eq!(a.congestion.cwnd(), 3500);
        if !ending {
            assert_eq!(a.congestion.ecn_prr_end(), Some(end));
            assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 0));
            assert_eq!(a.prr.unwrap().credit(), 500);
            a.write(&[2; 2000]).unwrap();
            let bytes = packet(&mut a, now + 1);
            let seg = wire::parse(ip(a.tuple()), &bytes).unwrap();
            assert_eq!(seg.header.sequence, end.0);
            assert_eq!(seg.payload.len(), 500);
            assert_ne!(seg.header.flags & CWR, 0);
            assert_eq!(a.prr.unwrap().credit(), 0);
            assert!(a.transmit(now + 1, &mut [0; 1500]).unwrap().is_none());
            let counters = a.prr.unwrap().counters();
            ack(&mut a, now + 2, end, true, &[]);
            assert_eq!(a.prr_exit_trace.unwrap().counters(), counters);
        }
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.ecn_prr_end(), None);
        assert_eq!(a.congestion.cwnd(), a.congestion.ssthresh());
        assert_eq!(a.congestion.cwnd(), 3500);
    }
}

#[test]
fn cubic_ecn_prr_rollback_below_threshold_uses_direct_window() {
    for basis in [1000, 2000] {
        for ending in [false, true] {
            let mut a = sender(true, false, 0, 1000);
            a.congestion.prr_window(basis);
            let base = a.snd_una;
            let end = a.snd_nxt;
            let now = pending_verification_rollback(&mut a, 500);
            ack(
                &mut a,
                now,
                if ending { end } else { base.wrapping_add(500) },
                true,
                &[],
            );
            let target = (basis * 7 / 10).max(1000) / 2;
            assert_eq!(a.mss, 500);
            assert_eq!(a.congestion.unsuppressed_cwnd(), target);
            assert_eq!(a.congestion.cwnd(), target);
            assert_eq!(a.congestion.ssthresh(), 1000);
            assert!(a.prr.is_none());
            assert_eq!(a.congestion.ecn_prr_end(), None);
            if !ending {
                ack(&mut a, now + 1, end, true, &[]);
                assert_eq!(a.congestion.cwnd(), target);
                assert!(a.prr.is_none());
            }
        }
    }
}

#[test]
fn cubic_ecn_prr_mss_divergence_drops_admission_without_inflation() {
    let mut a = sender(true, false, 0, 1000);
    a.set_path_mss(500);
    a.congestion.prr_window(2000);
    // Enabled path growth preserves byte windows, even below the new MSS floors.
    a.pmtud = Some(crate::pmtud::Pmtud::new(
        crate::PmtudConfig::new(1040),
        1040,
        true,
        600_000_000,
    ));
    a.pmtud.as_mut().unwrap().info.current_mtu = 540;
    let base = a.snd_una;
    ack(&mut a, 50, base.wrapping_add(250), true, &[]);
    assert_eq!(a.congestion.unsuppressed_cwnd(), 1400);
    assert_eq!(a.congestion.ssthresh(), 1400);
    assert!(a.prr.is_some());
    a.set_path_mss(1000);
    assert_eq!(a.congestion.unsuppressed_cwnd(), 1400);
    assert_eq!(a.congestion.ssthresh(), 1400);
    assert!(a.prr.is_some());
    a.set_path_mss(500);
    assert_eq!(a.congestion.unsuppressed_cwnd(), 700);
    assert_eq!(a.congestion.ssthresh(), 1000);
    assert_eq!(a.congestion.cwnd(), 700);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.ecn_prr_end(), None);
    let end = a.snd_nxt;
    ack(&mut a, 60, end, true, &[]);
    assert_eq!(a.congestion.cwnd(), 700);
    assert!(a.prr.is_none());
}

#[test]
fn cubic_ecn_prr_entry_ack_pmtu_growth_does_not_inflate_target() {
    for basis in [1000, 6000] {
        let mut a = sender(true, false, 0, 1000);
        a.set_path_mss(500);
        a.congestion.prr_window(basis);
        let mut p =
            crate::pmtud::Pmtud::new(crate::PmtudConfig::new(1040), 1040, true, 600_000_000);
        p.info.current_mtu = 540;
        p.start_probe(a.snd_una, 1000, 0, 1040);
        p.sent(a.snd_una, a.snd_nxt, 1040, 20, false);
        a.pmtud = Some(p);
        let end = a.snd_nxt;
        ack(&mut a, 50, end, true, &[]);
        assert_eq!(a.mss, 1000);
        assert_eq!(a.congestion.cwnd(), basis * 7 / 10);
        assert_eq!(a.congestion.ssthresh(), (basis * 7 / 10).max(1000));
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.ecn_prr_end(), None);
    }
}

#[test]
fn cubic_ecn_prr_new_ece_below_threshold_cancels_old_admission() {
    let mut a = sender(true, false, 0, 1000);
    a.congestion.prr_window(3000);
    let base = a.snd_una;
    ack(&mut a, 50, base.wrapping_add(500), true, &[]);
    assert_eq!(a.congestion.unsuppressed_cwnd(), 2100);
    assert!(a.prr.is_some());
    a.write(&[2; 1000]).unwrap();
    packet(&mut a, 51);
    ack(&mut a, 60, base.wrapping_add(1500), true, &[]);
    assert_eq!(a.congestion.cwnd(), 1470);
    assert_eq!(a.congestion.ssthresh(), 2000);
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.ecn_prr_end(), None);
    let end = a.snd_nxt;
    ack(&mut a, 61, end, true, &[]);
    assert_eq!(a.congestion.cwnd(), 1470);
}

#[test]
fn cubic_ecn_prr_loss_exit_below_threshold_preserves_direct_target() {
    for rollback in [false, true] {
        let mut a = sender(true, false, 0, 4000);
        let base = a.snd_una;
        ack(&mut a, 50, base.wrapping_add(1000), false, &[]);
        for delivered in [3333, 3666, 4000] {
            ack(
                &mut a,
                60,
                base.wrapping_add(1000),
                false,
                &[(base.wrapping_add(3000).0, base.wrapping_add(delivered).0)],
            );
        }
        assert!(a.congestion.in_recovery());
        assert_eq!(a.congestion.ssthresh(), 2100);
        a.write(&[2; 2000]).unwrap();
        packet(&mut a, 61); // Repair the head.
        ack(&mut a, 70, base.wrapping_add(3000), false, &[]);
        for _ in 0..2 {
            packet(&mut a, 71); // Fresh data beyond the loss boundary.
        }
        assert_eq!(a.snd_nxt, base.wrapping_add(6000));
        let now = if rollback {
            pending_verification_rollback(&mut a, 500)
        } else {
            80
        };
        ack(&mut a, now, base.wrapping_add(5000), true, &[]);
        assert!(!a.congestion.in_recovery());
        assert_eq!(a.congestion.cwnd(), if rollback { 735 } else { 1470 });
        assert_eq!(a.congestion.ssthresh(), if rollback { 1000 } else { 2000 });
        assert!(a.prr.is_none());
        assert_eq!(a.congestion.ecn_prr_end(), None);
    }
}

mod retransmit_delay_study {
    include!("connection_recovery_timing_tests.rs");

    mod local_tx_failure {
        include!("connection_local_tx_failure_tests.rs");
    }
}

#[test]
fn packetdrill_passive_ecn_cwr_prr_characterization() {
    extern crate std;
    use alloc::{format, string::String};
    let mut rows: Vec<String> = Vec::new();
    for algorithm in [PrrAlgorithm::Rfc9937, PrrAlgorithm::LegacyInitialCredit] {
        // Audited upstream,ecn baseline; no congestion/flight state fabrication.
        let cfg = ConnectionConfig {
            receive_capacity: 8 * 1024 * 1024,
            receive_ip_payload_limit: 65515,
            send_ip_payload_limit: 65515,
            initial_window: InitialWindow::Iw10,
            congestion_algorithm: CongestionAlgorithm::Cubic,
            cubic_hystart: true,
            cubic_fast_convergence: true,
            timestamps: true,
            sack: true,
            rack: true,
            tlp: true,
            prr: true,
            prr_algorithm: algorithm,
            prr_pacing: false,
            pacing: None,
            rto_min_us: 200_000,
            adaptive_ack: true,
            coalesce_read_window_updates: true,
            ecn: true,
            ..ConnectionConfig::default()
        };
        let metadata = ip(reverse(tuple()));
        let encode = |flags, seq, ack, window, options: &[u8]| {
            let mut bytes = vec![0; 60];
            let n = wire::encode(
                metadata,
                Header {
                    source_port: tuple().remote.port(),
                    destination_port: tuple().local.port(),
                    sequence: seq,
                    acknowledgment: ack,
                    flags,
                    window,
                    urgent_pointer: 0,
                },
                options,
                &[],
                &mut bytes,
            )
            .unwrap();
            bytes.truncate(n);
            bytes
        };
        let syn = encode(
            SYN | ECE | CWR,
            0,
            0,
            32792,
            &[2, 4, 3, 232, 1, 1, 4, 2, 1, 3, 3, 7],
        );
        let mut a = Connection::passive(
            tuple(),
            cfg,
            0,
            100_000,
            &wire::parse(metadata, &syn).unwrap(),
        )
        .unwrap();
        let bytes = packet(&mut a, 100_000);
        let synack = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(synack.header.flags, SYN | ACK | ECE);
        assert_eq!(synack.options.mss, Some(1460));
        assert_eq!(synack.options.window_scale, Some(8));
        assert!(synack.options.sack_permitted);
        let final_ack = encode(ACK, 1, 1, 320, &[]);
        a.input_with_traffic_class(200_000, 1, &wire::parse(metadata, &final_ack).unwrap())
            .unwrap();
        assert_eq!(a.state(), State::Established);
        assert!(a.ecn_send() && a.ecn_feedback() && a.sack_send && a.sack_receive);
        assert!(!a.timestamps);
        assert_eq!((a.mss, a.local_scale, a.peer_scale), (1000, 8, 7));
        assert_eq!((a.snd_wnd, a.ack_ato), (40960, 40_000));
        a.write(&[1; 4000]).unwrap();
        for i in 0..4 {
            let bytes = packet(&mut a, 200_000);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                (seg.header.sequence, seg.payload.len()),
                (1 + i * 1000, 1000)
            );
            assert_eq!(seg.header.flags & CWR, 0);
        }
        assert_eq!(a.transport_info_at(205_000).cwnd, 10_000);
        assert_eq!((a.data_flight(), a.rack.pipe()), (4000, 4000));
        assert!(a.prr.is_none());
        let snapshot = |a: &Connection, event: &str, at, rows: &mut Vec<String>| {
            let (fs, delivered, out, credit) = a.prr.map_or((0, 0, 0, 0), |p| {
                let (fs, delivered, out) = p.counters();
                (fs, delivered, out, p.credit())
            });
            rows.push(format!(
                concat!(
                    "{{\"algorithm\":\"{:?}\",\"event\":\"{}\",\"at_us\":{},",
                    "\"cwnd_bytes\":{},\"logical_cwnd_bytes\":{},\"ssthresh_bytes\":{},",
                    "\"flight_bytes\":{},\"pipe_bytes\":{},\"recover_fs\":{},",
                    "\"delivered\":{},\"out\":{},\"credit\":{},\"lost\":{},",
                    "\"ecn_response\":{},\"cwr_pending\":{},\"rto_deadline\":{:?}}}"
                ),
                algorithm,
                event,
                at,
                a.congestion.cwnd(),
                a.congestion.unsuppressed_cwnd(),
                a.congestion.ssthresh(),
                a.data_flight(),
                a.rack.pipe(),
                fs,
                delivered,
                out,
                credit,
                a.rack.counts().lost,
                a.transport_info_at(at).ecn_response,
                a.ecn_cwr_pending,
                a.rto_deadline.unwrap()
            ));
        };
        snapshot(&a, "before_ece", 205_000, &mut rows);
        inject(&mut a, 300_000, Seq(1), Seq(1001), ACK | ECE, 320, &[]); // Not-ECT.
        assert_eq!(a.congestion.ssthresh(), 7000);
        assert_eq!(a.congestion.unsuppressed_cwnd(), 7000);
        assert_eq!((a.data_flight(), a.rack.pipe()), (3000, 3000));
        assert_eq!(a.rack.counts().lost, 0);
        assert!(!a.retx_pending && !a.congestion.in_recovery());
        assert!(a.rack.deadline.is_none());
        assert!(a.ecn_cwr_pending && a.transport_info_at(305_000).ecn_response);
        assert!(a.next_deadline().unwrap() > 305_000);
        snapshot(&a, "after_ece", 305_000, &mut rows);
        if algorithm == PrrAlgorithm::LegacyInitialCredit {
            // This control omits modern ECN PRR; it is not RFC6937 CWR emulation.
            assert!(a.prr.is_none());
            assert_eq!(a.congestion.cwnd(), 7000);
            continue;
        }
        assert_eq!(a.congestion.ecn_prr_end(), Some(Seq(4001)));
        assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 0));
        assert_eq!(a.prr.unwrap().credit(), 2000);
        assert_eq!(
            (a.transport_info().cwnd, a.transport_info().mss),
            (5000, 1000)
        );
        // Equation-only control with the same inputs: do not mutate the connection.
        let mut unsafe_equation = Prr::new(4000, 1000, PrrAlgorithm::Rfc9937);
        unsafe_equation.acknowledge(1000, 3000, 7000, false);
        assert_eq!(unsafe_equation.credit(), 1000);
        inject(&mut a, 305_001, Seq(1), Seq(1001), ACK | ECE, 320, &[]);
        assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 0));
        assert_eq!(a.prr.unwrap().credit(), 2000);
        assert_eq!(a.congestion.ssthresh(), 7000);
        assert!(a.transmit(305_001, &mut [0; 1500]).unwrap().is_none());
        assert!(a.ecn_cwr_pending);
        snapshot(&a, "repeated_ece_no_delivery", 305_001, &mut rows);
        // Counterfactual continuation beyond the fixture: test real admission.
        a.write(&[2; 3000]).unwrap();
        for i in 0..2 {
            let bytes = packet(&mut a, 306_000);
            let seg = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                (seg.header.sequence, seg.payload.len()),
                (4001 + i * 1000, 1000)
            );
            assert_eq!(seg.header.flags & CWR != 0, i == 0);
        }
        assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 2000));
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.data_flight(), 5000);
        assert!(!a.ecn_cwr_pending);
        assert!(a.transmit(306_000, &mut [0; 1500]).unwrap().is_none());
        snapshot(&a, "counterfactual_two_fresh_segments", 306_000, &mut rows);
    }
    if let Ok(path) = std::env::var("NTCP_ECN_CWR_STATE_PATH") {
        std::fs::write(path, format!("[\n{}\n]\n", rows.join(",\n"))).unwrap();
    }
}

mod remaining17_study {
    include!("connection_remaining17_tests.rs");

    mod push_boundary {
        include!("connection_push_boundary_tests.rs");
    }
}
