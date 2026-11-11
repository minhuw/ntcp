use super::*;
use crate::connection::test_support::commit_reserved;

#[test]
fn reserved_nonhead_sack_retry_keeps_exhausted_prr_credit_and_recovery_state() {
    use crate::output_reservation::OutputReservation;
    for iss in [0, u32::MAX - 4999] {
        let mut a = rack_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        packet(&mut a, 200_000);
        strict_ack(&mut a, 200_001, 1000, &[(7000, 10_000)]);
        let mut bytes = [0; 2048];
        let mut last = 0;
        for _ in 0..20 {
            let Some(n) = a.transmit_selected(200_001, &mut bytes, true).unwrap() else {
                break;
            };
            last = n;
            if a.prr.unwrap().credit() == 0 {
                break;
            }
        }
        assert_eq!(a.prr.unwrap().credit(), 0);
        let segment = wire::parse(ip(tuple()), &bytes[..last]).unwrap();
        let sequence = segment.header.sequence;
        let payload = segment.payload.to_vec();
        assert_ne!(Seq(sequence), a.snd_una);
        assert!(!payload.is_empty());
        let mut reservation = OutputReservation::new();
        reservation.bytes.resize(2048, 0);
        let token = reservation.token().unwrap();
        reservation.capture(
            crate::Transmit {
                connection: None,
                tx_timestamp: None,
                ipv4_options: Default::default(),
                ecn: 0,
                ip: ip(tuple()),
                len: last,
                hop_limit: 64,
                dscp: 0,
            },
            &bytes,
            token,
        );
        a.lower_mss(64).unwrap();
        let counters = a.prr.unwrap().counters();
        let recovery = a.sack_recovery.map(|r| (r.high_rxt, r.rescue_rxt, r.pipe));
        let boundaries = (a.snd_nxt, a.snd_una, a.send_base, a.send.len());
        assert_eq!(a.transmit(200_001, &mut [0; 2048]).unwrap(), None);
        let mut total = 0;
        let mut departure = a.last_departure.unwrap();
        crate::allocation_tests::fail_after(0, || {
            loop {
                let p = reservation.fragment(84, &mut bytes).unwrap();
                let s = wire::parse(p.ip, &bytes[..p.len]).unwrap();
                assert_eq!(s.header.sequence, sequence.wrapping_add(total as u32));
                assert_eq!(s.payload, &payload[total..total + s.payload.len()]);
                let count = s.payload.len();
                let r = reservation.current.as_mut().unwrap();
                a.accept_reserved_output(
                    400_000 + total as u64,
                    &mut departure,
                    total,
                    count,
                    r.finished,
                )
                .unwrap();
                total += count;
                if r.finished {
                    break;
                }
                r.offset += r.emitted_bytes;
                r.sacks += r.emitted_sacks;
            }
        });
        assert_eq!(total, payload.len());
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.prr.unwrap().counters(), counters);
        assert_eq!(
            a.sack_recovery.map(|r| (r.high_rxt, r.rescue_rxt, r.pipe)),
            recovery
        );
        assert_eq!(
            (a.snd_nxt, a.snd_una, a.send_base, a.send.len()),
            boundaries
        );
    }
}

#[test]
fn reserved_rejection_withdraws_only_latest_recorded_pmtu_attempt() {
    let (mut a, _) = pair(
        ConnectionConfig {
            pmtud: Some(crate::PmtudConfig::new(1500)),
            nagle: false,
            ..config(1024, 128)
        },
        100,
    );
    a.write(b"local rejection").unwrap();
    packet(&mut a, 40);
    let range = a.last_pmtu_output.unwrap();
    let info = a.path_mtu_info();
    let counters = (a.snd_nxt, a.congestion.cwnd(), a.congestion.ssthresh());
    a.reject_reserved_output();
    assert!(a.last_pmtu_output.is_none());
    assert!(!a.pmtud.as_mut().unwrap().reject_latest(range.0, range.1));
    assert_eq!(a.path_mtu_info(), info);
    assert_eq!(
        (a.snd_nxt, a.congestion.cwnd(), a.congestion.ssthresh()),
        counters
    );

    a.write(b"another output").unwrap();
    packet(&mut a, 41);
    let range = a.last_pmtu_output.unwrap();
    a.ack_pending = true;
    packet(&mut a, 42);
    assert!(a.last_pmtu_output.is_none());
    a.reject_reserved_output();
    // A rejected pure ACK cannot erase an older sequence-bearing attempt.
    assert!(a.pmtud.as_mut().unwrap().reject_latest(range.0, range.1));
}

#[test]
fn reserved_departure_preserves_older_flight_and_fragment_ages() {
    for iss in [100, u32::MAX - 50] {
        let cfg = ConnectionConfig {
            nagle: false,
            tlp: false,
            ..config(1024, 100)
        };
        let (mut a, _) = pair(cfg.clone(), iss);
        a.write(&[1; 200]).unwrap();
        packet(&mut a, 40);
        let deadline = a.rto_deadline;
        let head = a.rack.head_transmission(a.snd_una);
        a.transmit_selected(41, &mut [0; 2048], true)
            .unwrap()
            .unwrap();
        let mut d = a.last_departure.unwrap();
        assert!(!d.rto); // Fresh tail does not own the older flight's timer.
        let late = deadline.unwrap() + 1;
        a.accept_reserved_output(late, &mut d, 0, 100, true)
            .unwrap();
        assert_eq!(a.rto_deadline, deadline);
        assert_eq!(a.rack.head_transmission(a.snd_una), head);
        a.timeout(late).unwrap();
        assert_eq!(a.consecutive_timeouts, 1);

        let (mut a, _) = pair(cfg, iss);
        a.write(&[1; 100]).unwrap();
        a.shutdown().unwrap();
        a.transmit_selected(40, &mut [0; 2048], true)
            .unwrap()
            .unwrap();
        let mut d = a.last_departure.unwrap();
        let start = a.snd_una;
        let counters = (a.snd_nxt, a.rack.counts().retransmitted);
        a.accept_reserved_output(2_000_000, &mut d, 0, 31, false)
            .unwrap();
        let deadline = a.rto_deadline;
        assert_eq!(
            a.rack.head_transmission(start),
            Some((start.wrapping_add(31), 2_000_000))
        );
        a.accept_reserved_output(2_100_000, &mut d, 31, 69, true)
            .unwrap();
        assert_eq!(a.rto_deadline, deadline);
        assert_eq!(a.fin_sent_at, Some(2_100_000));
        assert_eq!(
            a.rack.head_transmission(start),
            Some((start.wrapping_add(31), 2_000_000))
        );
        assert_eq!(
            a.rack.head_transmission(start.wrapping_add(31)),
            Some((start.wrapping_add(100), 2_100_000))
        );
        assert_eq!((a.snd_nxt, a.rack.counts().retransmitted), counters);
        assert!(a.sample.is_none());
        let cwnd = a.congestion.cwnd();
        a.timeout(2_100_000).unwrap();
        assert_eq!(a.congestion.cwnd(), cwnd);
        a.timeout(deadline.unwrap()).unwrap();
        assert_eq!(a.consecutive_timeouts, 1);
    }
}

#[test]
fn reserved_control_departure_owns_only_its_timers() {
    let cfg = ConnectionConfig {
        tlp: false,
        ..config(1024, 100)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
    a.transmit_selected(0, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert!(d.syn && d.rto);
    a.accept_reserved_output(2_000_000, &mut d, 0, 0, true)
        .unwrap();
    assert_eq!(a.rto_deadline, Some(2_000_000 + a.rto()));
    a.timeout(2_000_000).unwrap();
    assert_eq!(a.syn_retransmissions, 0);
    assert_eq!(a.sample, Some((Seq(101), 0)));
    assert_eq!(a.sample_departure, Some(2_000_000));

    let (mut a, _) = pair(cfg.clone(), 100);
    a.shutdown().unwrap();
    a.transmit_selected(40, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert!(d.fin && d.rto);
    a.accept_reserved_output(2_000_000, &mut d, 0, 0, true)
        .unwrap();
    assert_eq!(a.fin_sent_at, Some(2_000_000));
    assert_eq!(a.rto_deadline, Some(2_000_000 + a.rto()));
    a.timeout(2_000_000).unwrap();
    assert_eq!(a.consecutive_timeouts, 0);

    let (mut a, _) = pair(cfg, 100);
    a.write(&[1; 100]).unwrap();
    a.snd_wnd = 0;
    a.probe_pending = true;
    a.persist_interval = a.rto();
    a.transmit_selected(40, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert!(d.persist && d.bypass && !d.rto);
    let interval = a.persist_interval;
    a.accept_reserved_output(2_000_000, &mut d, 0, 0, true)
        .unwrap();
    assert_eq!(a.persist_interval, interval); // no second probe/backoff charge
    assert_eq!(a.persist_unanswered_since, Some(2_000_000));
    assert_eq!(
        a.rto_deadline.or(a.persist_deadline),
        Some(2_000_000 + interval)
    );
}

#[test]
fn reserved_probe_pacing_preserves_prior_debt_and_options_ack_costs_nothing() {
    for general in [false, true] {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            tlp: true,
            nagle: false,
            prr: !general,
            prr_pacing: true,
            pacing: general.then_some(PacingConfig {
                initial_window_burst: false,
                max_burst_segments: 1,
                ..Default::default()
            }),
            ..config(1024, 100)
        };
        let (mut a, _) = pair(cfg, 100);
        a.write(&[1; 200]).unwrap();
        packet(&mut a, 40);
        let previous = (a.pacer, a.pacing_deadline);
        assert!(a.pacing_deadline.is_some_and(|at| at > 40));
        a.tlp_pending = true;
        a.tlp_fresh_rtt = true;
        a.transmit_selected(40, &mut [0; 2048], true)
            .unwrap()
            .unwrap();
        let mut d = a.last_departure.unwrap();
        assert!(d.bypass && d.rto && !d.tlp);
        assert_eq!((a.pacer, a.pacing_deadline), previous);
        assert_eq!(a.reserved_pacing_deadline(40, &d), None);
        let selected = (
            a.snd_nxt,
            a.tlp_end,
            a.tlp_flight,
            a.rack.counts().retransmitted,
        );
        // A retained-options-only fragment cannot acquire the selected data's debt
        // or consume its RTO restart ownership.
        a.accept_reserved_output(40, &mut d, 0, 0, false).unwrap();
        assert_eq!((a.pacer, a.pacing_deadline), previous);
        assert!(d.rto);
        let mut expected_pacer = a.pacer;
        if let Some(interval) = d.interval {
            expected_pacer.sent(40, 100, interval);
        }
        a.accept_reserved_output(40, &mut d, 0, 100, true).unwrap();
        assert_eq!(a.pacer, expected_pacer);
        if let Some((rtt, cwnd)) = d.legacy_rate {
            let spacing = (100 * rtt as u128).div_ceil(cwnd as u128).max(1) as u64;
            assert_eq!(a.pacing_deadline, Some(previous.1.unwrap() + spacing));
        }
        assert_eq!(
            (
                a.snd_nxt,
                a.tlp_end,
                a.tlp_flight,
                a.rack.counts().retransmitted
            ),
            selected
        );
        assert!(a.tlp_deadline.is_none());
    }
}

#[test]
fn reserved_tlp_departure_and_overdue_older_flight_timer_ownership() {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        tlp: true,
        nagle: false,
        ..config(1024, 100)
    };
    let (mut a, _) = pair(cfg.clone(), 100);
    a.write(&[1; 100]).unwrap();
    packet(&mut a, 40);
    a.tlp_pending = true;
    a.tlp_fresh_rtt = true;
    a.transmit_selected(50, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert!(d.bypass && d.rto && !d.tlp);
    let selected = (a.tlp_end, a.tlp_flight, a.rack.counts().retransmitted);
    a.accept_reserved_output(2_000_000, &mut d, 0, 100, true)
        .unwrap();
    assert_eq!(a.rto_deadline, Some(2_000_000 + a.rto()));
    assert_eq!(
        (a.tlp_end, a.tlp_flight, a.rack.counts().retransmitted),
        selected
    );
    assert_eq!(a.tlp_deadline, None);
    a.timeout(2_000_000).unwrap();
    assert_eq!(a.consecutive_timeouts, 0);

    let (mut a, _) = pair(cfg, 100);
    a.write(&[1; 200]).unwrap();
    packet(&mut a, 40);
    let deadline = a.rto_deadline.unwrap();
    a.transmit_selected(41, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert!(d.tlp && !d.rto);
    a.accept_reserved_output(deadline + 1, &mut d, 0, 100, true)
        .unwrap();
    assert_eq!(a.rto_deadline, Some(deadline));
    assert_eq!(a.loss_timer, Some((LossTimer::Rto, deadline)));
    a.timeout(deadline + 1).unwrap();
    assert_eq!(a.consecutive_timeouts, 1);
}

#[test]
fn reserved_fresh_rtt_uses_departure_not_retained_timestamp_selection() {
    let (mut a, _) = pair(
        ConnectionConfig {
            timestamps: true,
            sack: true,
            rack: true,
            ..config(1024, 100)
        },
        100,
    );
    a.write(&[1; 100]).unwrap();
    a.transmit_selected(40, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let echo = a.timestamp_value(40);
    commit_reserved(&mut a, 2_000_000);
    assert!(a.sample.is_none());
    let mut expected = a.rtt.clone();
    expected.sample(100);
    let (next, end) = (a.receive.next(), a.snd_nxt);
    timestamp_input(&mut a, 2_000_100, next, end, ACK, Some((2000, echo)), b"");
    assert_eq!(a.rack.ack_sample, Some(100));
    assert_eq!(
        (a.rtt.srtt(), a.rtt.variance(), a.rtt.rto()),
        (expected.srtt(), expected.variance(), expected.rto())
    );
}

#[test]
fn reserved_nonhead_retry_preserves_advancing_ack_rto_restart() {
    for delay in [0, 50_000, 1_000_000] {
        let mut a = rack_flight(0);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        packet(&mut a, 200_000);
        strict_ack(&mut a, 200_001, 1000, &[(7000, 10_000)]);
        while a.prr.unwrap().credit() != 0 {
            packet(&mut a, 200_001);
        }
        strict_ack(&mut a, 300_000, 2000, &[(7000, 10_000)]);
        let deadline = a.rto_deadline.unwrap();
        let head = a.rack.head_transmission(a.snd_una).unwrap();
        assert!(head.1 + a.rto() < deadline);
        let mut bytes = [0; 2048];
        a.transmit_selected(300_000, &mut bytes, true)
            .unwrap()
            .unwrap();
        let mut d = a.last_departure.unwrap();
        assert_ne!(Seq(d.start), a.snd_una);
        assert!(d.rto && !d.rto_head);
        let count = d.payload;
        a.accept_reserved_output(300_000 + delay, &mut d, 0, count, true)
            .unwrap();
        assert_eq!(a.rack.head_transmission(a.snd_una), Some(head));
        assert_eq!(a.rto_deadline, Some(deadline));
        if a.now < deadline {
            a.timeout(deadline - 1).unwrap();
            assert_eq!(a.consecutive_timeouts, 0);
        }
        a.timeout(a.now.max(deadline)).unwrap();
        assert_eq!(a.consecutive_timeouts, 1);
        // A genuine timeout selects the head and does own a new departure anchor.
        a.transmit_selected(a.now, &mut bytes, true)
            .unwrap()
            .unwrap();
        let mut d = a.last_departure.unwrap();
        assert!(d.rto && d.rto_head);
        let count = d.payload;
        let now = a.now + 50_000;
        a.accept_reserved_output(now, &mut d, 0, count, true)
            .unwrap();
        assert_eq!(a.rto_deadline, Some(now + a.rto()));
        a.timeout(now).unwrap();
        assert_eq!(a.consecutive_timeouts, 1);
        a.timeout(a.rto_deadline.unwrap()).unwrap();
        assert_eq!(a.consecutive_timeouts, 2);
    }
}

#[test]
fn reserved_stale_history_discards_evidence_not_departure_obligation() {
    let cfg = ConnectionConfig {
        timestamps: true,
        timestamp_granularity: TimestampGranularity::Microseconds,
        user_timeout_us: 10_000_000_000,
        pmtud: Some(crate::PmtudConfig::new(1500)),
        sack: true,
        rack: true,
        tlp: false,
        ..config(1024, 100)
    };
    let (mut a, _) = pair(cfg, 100);
    a.write(&[1; 100]).unwrap();
    a.transmit_selected(40, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert!(a.reserved_ledger.is_some());
    a.set_reserved_first_hop_mtu(40 + (1 << 30), 1400).unwrap();
    assert!(a.rack.valid());
    let now = 40 + (1 << 31);
    a.set_reserved_first_hop_mtu(now, 1400).unwrap();
    assert!(!a.rack.valid());
    assert!(a.reserved_ledger.is_none());
    assert!(a.sample.is_none() && a.last_timestamp_sent_at.is_none());
    a.accept_reserved_output(now, &mut d, 0, 40, false).unwrap();
    let deadline = a.rto_deadline;
    let remaining = d.payload - 40;
    a.accept_reserved_output(now + 1, &mut d, 40, remaining, true)
        .unwrap();
    assert!(!a.rack.valid()); // No old TS/retry history is resurrected.
    assert_eq!(a.rto_deadline, deadline);
    a.timeout(now + 1).unwrap();
    assert_eq!(a.consecutive_timeouts, 0);
    a.timeout(deadline.unwrap()).unwrap();
    assert_eq!(a.consecutive_timeouts, 1);
}

fn gso_select(
    a: &mut Connection,
    now: Instant,
    payload: &mut [u8],
    bytes: &mut [u8],
) -> Option<usize> {
    a.transmit_selected_with_gso(
        now,
        bytes,
        true,
        Some(crate::output_reservation::GsoBuffer {
            limits: crate::GsoLimits {
                max_bytes: payload.len(),
                max_segments: 4,
            },
            payload,
        }),
    )
    .unwrap()
}

#[test]
fn gso_wrap_eor_cwr_rack_physical_segments_and_no_hotpath_allocation() {
    for iss in [100, u32::MAX - 150] {
        let cfg = ConnectionConfig {
            nagle: false,
            sack: true,
            rack: true,
            ecn: true,
            initial_window: InitialWindow::Iw10,
            ..config(4096, 100)
        };
        let (mut a, _) = pair(cfg.clone(), iss);
        let (mut scalar, _) = pair(cfg, iss);
        for c in [&mut a, &mut scalar] {
            c.write_with_options(&[3; 300], false, true).unwrap();
            c.write(&[4; 100]).unwrap();
            c.ecn_cwr_pending = true;
        }
        let mut reservation = crate::output_reservation::OutputReservation::new();
        reservation.bytes.resize(2048, 0);
        reservation.payload.resize(1000, 0);
        let mut bytes = [0; 2048];
        let n = crate::allocation_tests::fail_after(0, || {
            gso_select(&mut a, 40, &mut reservation.payload, &mut bytes).unwrap()
        });
        let mut departure = a.last_departure.unwrap();
        let s = departure.segmentation.unwrap();
        assert_eq!(s.payload_len, 300); // Never crosses the EOR.
        assert_eq!(s.segment_payload_len, 100);
        let start = Seq(departure.start);
        assert_eq!(a.snd_nxt, start.wrapping_add(300));
        let token = reservation.token().unwrap();
        reservation.capture(
            crate::Transmit {
                connection: None,
                tx_timestamp: None,
                ipv4_options: Default::default(),
                ecn: 2,
                ip: ip(tuple()),
                len: n,
                hop_limit: 64,
                dscp: 0,
            },
            &bytes,
            token,
        );
        reservation.current.as_mut().unwrap().departure = Some(departure);
        crate::allocation_tests::fail_after(0, || {
            for segment in 0..3 {
                let p = reservation.fragment(120, &mut bytes).unwrap();
                let parsed = wire::parse(p.ip, &bytes[..p.len]).unwrap();
                assert_eq!(parsed.header.sequence, start.wrapping_add(segment * 100).0);
                assert_eq!(parsed.header.flags & CWR != 0, segment == 0);
                assert_eq!(parsed.header.flags & PSH != 0, segment == 2);
                let mut expected = [0; 2048];
                let n = scalar.transmit(40, &mut expected).unwrap().unwrap();
                assert_eq!(&bytes[..p.len], &expected[..n]);
                let r = reservation.current.as_mut().unwrap();
                a.accept_reserved_output(
                    50 + segment as u64,
                    &mut departure,
                    r.offset,
                    r.emitted_bytes,
                    r.finished,
                )
                .unwrap();
                // Each accepted segment has its own sequence end and actual time;
                // neither earlier acceptance nor the selection's aggregate end wins.
                assert_eq!(
                    a.rack.head_transmission(start.wrapping_add(segment * 100)),
                    Some((start.wrapping_add((segment + 1) * 100), 50 + segment as u64))
                );
                r.offset += r.emitted_bytes;
            }
        });
        assert_eq!(a.snd_nxt, start.wrapping_add(300)); // Acceptance never recharges.
        assert_eq!(a.rack.counts().retransmitted, 0);
        assert_eq!(a.rack.counts().lost, 0);
        assert_eq!(
            a.rack.head_transmission(start),
            Some((start.wrapping_add(100), 50))
        );
    }
}

#[test]
fn gso_full_range_credit_bounds_and_scalar_nagle_cork_tail() {
    for (window, byte_limit, expected) in [(250, 1000, 200), (1000, 250, 200), (1000, 1000, 400)] {
        let (mut a, _) = pair(
            ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                ..config(4096, 100)
            },
            0,
        );
        a.snd_wnd = window;
        a.write(&[1; 1000]).unwrap();
        let mut payload = vec![0; byte_limit];
        gso_select(&mut a, 40, &mut payload, &mut [0; 2048]).unwrap();
        let d = a.last_departure.unwrap();
        assert_eq!(d.segmentation.unwrap().payload_len, expected);
        assert_eq!(a.flight() as usize, expected);
    }
    // Real initial cwnd=10*MSS, aggregate bounds must not extend it.
    let (mut a, _) = pair(config(4096, 100), 0);
    let cwnd = a.congestion.cwnd() as usize;
    a.write(&[1; 2000]).unwrap();
    let mut payload = [0; 2000];
    a.transmit_selected_with_gso(
        40,
        &mut [0; 2048],
        true,
        Some(crate::output_reservation::GsoBuffer {
            limits: crate::GsoLimits {
                max_bytes: 2000,
                max_segments: 20,
            },
            payload: &mut payload,
        }),
    )
    .unwrap()
    .unwrap();
    assert_eq!(a.last_departure.unwrap().payload, cwnd / 100 * 100);
    for cork in [false, true] {
        let (mut a, _) = pair(config(4096, 100), 0);
        a.set_cork(cork);
        a.write(&[1; 250]).unwrap();
        gso_select(&mut a, 40, &mut payload, &mut [0; 2048]).unwrap();
        assert_eq!(
            a.last_departure.unwrap().segmentation.unwrap().payload_len,
            200
        );
        assert_eq!(gso_select(&mut a, 41, &mut payload, &mut [0; 2048]), None);
    }
}

#[test]
fn gso_conservative_fallbacks_keep_scalar_paths() {
    // A queued FIN (former case 0), recovery's PRR credit (former cases 5
    // and 11) and timeout recovery (former case 9) admit groups:
    // transmit_group_tests.
    for case in (1..11).filter(|&case| ![5, 8, 9].contains(&case)) {
        let cfg = ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            congestion_algorithm: CongestionAlgorithm::Reno,
            ..config(4096, 100)
        };
        let (mut a, _) = pair(cfg, 0);
        a.write(&[1; 1000]).unwrap();
        match case {
            1 => a.snd_up = Some(a.snd_nxt.wrapping_add(900)),
            2 => a.retx_pending = true,
            3 => a.probe_pending = true,
            4 => a.tlp_pending = true,
            6 => a.config.pacing = Some(crate::PacingConfig::default()),
            7 => {
                a.config.prr = true;
                a.config.prr_pacing = true;
            }
            10 => {
                a.tx_timestamps.resize(1, usize::MAX).unwrap();
                a.tx_timestamps.insert(
                    crate::TxTimestampRequest {
                        cookie: 1,
                        software_transmit: true,
                        ..Default::default()
                    },
                    999,
                );
            }
            _ => unreachable!(),
        }
        let mut payload = [0; 1000];
        let out = gso_select(&mut a, 40, &mut payload, &mut [0; 2048]);
        if out.is_some() {
            assert_eq!(a.last_departure.unwrap().segmentation, None, "case {case}");
            assert!(a.last_departure.unwrap().payload <= 100, "case {case}");
        }
    }
    // Fresh writes with earlier application PUSH marks must not move those marks.
    let (mut a, _) = pair(config(4096, 100), 0);
    a.write(&[1; 100]).unwrap();
    a.write(&[2; 300]).unwrap();
    gso_select(&mut a, 40, &mut [0; 1000], &mut [0; 2048]);
    assert_eq!(a.last_departure.unwrap().segmentation, None);
    // A real SACK loss-recovery selection stays on its existing PRR path.
    let mut a = rack_flight(0);
    strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
    gso_select(&mut a, 200_000, &mut [0; 4000], &mut [0; 2048]).unwrap();
    assert_eq!(a.last_departure.unwrap().segmentation, None);
}

#[test]
fn gso_pmtu_probe_sack_and_timestamp_credit_fallbacks() {
    let (mut a, _) = pair(
        ConnectionConfig {
            pmtud: Some(crate::PmtudConfig::new(1500)),
            initial_window: InitialWindow::Iw10,
            ..config(8192, 1000)
        },
        0,
    );
    a.write(&[1; 6000]).unwrap();
    gso_select(&mut a, 40, &mut [0; 6000], &mut [0; 2048]).unwrap();
    assert!(a.pmtud.as_ref().unwrap().probe.is_some());
    assert_eq!(a.last_departure.unwrap().segmentation, None);

    let (mut a, _) = pair(
        ConnectionConfig {
            sack: true,
            ..config(4096, 100)
        },
        0,
    );
    let (next, ack) = (a.receive.next(), a.snd_una);
    inject(&mut a, 35, next.wrapping_add(10), ack, ACK, 4096, b"gap");
    a.write(&[1; 1000]).unwrap();
    let mut bytes = [0; 2048];
    let n = gso_select(&mut a, 40, &mut [0; 1000], &mut bytes).unwrap();
    let parsed = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
    assert!(parsed.options.sack_blocks.iter().any(Option::is_some));
    assert_eq!(a.last_departure.unwrap().segmentation, None);

    let (mut a, _) = pair(
        ConnectionConfig {
            timestamps: true,
            timestamp_bytes_per_tick: 220,
            initial_window: InitialWindow::Iw10,
            ..config(4096, 100)
        },
        0,
    );
    a.write(&[1; 1000]).unwrap();
    let before = (
        a.snd_nxt,
        a.timestamp_bytes,
        a.rack.counts().unacked,
        a.send.len(),
    );
    assert_eq!(
        a.transmit_selected_with_gso(
            40,
            &mut [0; 31],
            true,
            Some(crate::output_reservation::GsoBuffer {
                limits: crate::GsoLimits {
                    max_bytes: 1000,
                    max_segments: 4
                },
                payload: &mut [0; 1000]
            })
        ),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(
        (
            a.snd_nxt,
            a.timestamp_bytes,
            a.rack.counts().unacked,
            a.send.len()
        ),
        before
    );
    gso_select(&mut a, 40, &mut [0; 1000], &mut bytes).unwrap();
    let s = a.last_departure.unwrap().segmentation.unwrap();
    assert_eq!(s.payload_len, 176); // Two option-adjusted 88-byte segments.
    assert!(a.timestamp_bytes <= 220);
}

#[test]
fn group_preflight_and_same_submit_time_keep_rack_spans_and_first_timer_across_wrap() {
    for iss in [100, u32::MAX - 150] {
        let cfg = ConnectionConfig {
            nagle: false,
            sack: true,
            rack: true,
            initial_window: InitialWindow::Iw10,
            ..config(4096, 100)
        };
        let (mut a, _) = pair(cfg, iss);
        a.write(&[3; 400]).unwrap();
        let mut bytes = [0; 2048];
        let mut payload = [0; 1000];
        gso_select(&mut a, 40, &mut payload, &mut bytes).unwrap();
        let mut departure = a.last_departure.unwrap();
        let start = Seq(departure.start);
        let nxt = a.snd_nxt;
        crate::allocation_tests::fail_after(0, || {
            for n in 0..3 {
                a.accept_reserved_output(50, &mut departure, n * 100, 100, false)
                    .unwrap();
            }
        });
        let timer = a.rto_deadline;
        assert_eq!(timer, Some(50 + a.rto()));
        for n in 0..3 {
            let left = start.wrapping_add(n * 100);
            let right = start.wrapping_add((n + 1) * 100);
            assert_eq!(
                crate::rack::tests::original_packet(&a.rack, left),
                Some((left, right, 50, false))
            );
            assert_eq!(a.rack.head_transmission(left), Some((right, 50)));
        }
        assert_eq!(a.snd_nxt, nxt);
        assert!(!departure.rto);
        a.accept_reserved_output(70, &mut departure, 300, 100, true)
            .unwrap();
        assert_eq!(a.rto_deadline, timer);
        assert_eq!(a.snd_nxt, nxt);
        assert_eq!(
            a.rack.head_transmission(start.wrapping_add(300)),
            Some((start.wrapping_add(400), 70))
        );
    }
}

#[test]
fn actual_group_flush_follows_admission_not_a_fixed_segment_count() {
    for (queued, storage, window) in [
        (2500, 8000, 16000),
        (4500, 8000, 16000),
        (7500, 2500, 16000),
        (7500, 8000, 2500),
    ] {
        let (mut a, _) = pair(
            ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                output_group_flush: true,
                ..config(16384, 1000)
            },
            u32::MAX - 1500,
        );
        a.snd_wnd = window;
        a.write(&vec![7; queued]).unwrap();
        let mut payload = vec![0; storage];
        let mut bytes = [0; 2048];
        let expected = (queued / 1000)
            .min(storage / 1000)
            .min(window as usize / 1000)
            .min(4)
            .min((a.congestion.cwnd() as usize / 1000 / 2).max(1))
            * 1000;
        let n = crate::allocation_tests::fail_after(0, || {
            gso_select(&mut a, 40, &mut payload, &mut bytes)
        })
        .unwrap();
        let d = a.last_departure.unwrap();
        let segmentation = d.segmentation.unwrap();
        assert_eq!(segmentation.payload_len, expected);
        assert_ne!(segmentation.terminal_flags & PSH, 0);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes[..n]).unwrap().header.flags & PSH,
            0
        );
        // Optional group flush never becomes an application mark retained by
        // retries. Only the original SEND terminal byte carries that intent.
        assert!(!a.send.pushed(0, queued - 1));
        assert!(a.send.pushed(queued - 1, 1));
        assert!(a.flight() <= a.snd_wnd.min(a.congestion.cwnd()));
    }
}

#[test]
fn actual_group_flush_preserves_no_push_and_application_terminal() {
    for push in [false, true] {
        let (mut a, _) = pair(
            ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                output_group_flush: true,
                ..config(16384, 1000)
            },
            0,
        );
        a.write_with_push(&[3; 4000], push).unwrap();
        let mut payload = [0; 8000];
        gso_select(&mut a, 40, &mut payload, &mut [0; 2048]).unwrap();
        let d = a.last_departure.unwrap();
        assert_eq!(d.segmentation.unwrap().payload_len, 4000);
        assert_eq!(d.segmentation.unwrap().terminal_flags & PSH != 0, push);
        assert!(!a.send.pushed(0, 3999));
        assert_eq!(a.send.pushed(3999, 1), push);
    }
}

#[test]
fn actual_group_flush_failed_encoding_cannot_create_an_application_mark() {
    let (mut a, _) = pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            output_group_flush: true,
            ..config(16384, 1000)
        },
        0,
    );
    a.write(&[5; 7000]).unwrap();
    let before = (a.snd_nxt, a.flight(), a.rack.counts().unacked);
    let mut payload = [0; 8000];
    assert_eq!(
        a.transmit_selected_with_gso(
            40,
            &mut [],
            true,
            Some(crate::output_reservation::GsoBuffer {
                limits: crate::GsoLimits {
                    max_bytes: 8000,
                    max_segments: 8
                },
                payload: &mut payload,
            })
        ),
        Err(Error::OutputTooSmall)
    );
    assert_eq!((a.snd_nxt, a.flight(), a.rack.counts().unacked), before);
    assert!(!a.send.pushed(0, 6999));
    assert!(a.send.pushed(6999, 1));
}

#[test]
fn actual_group_flush_tracks_final_accepted_fragment_through_mtu_shrink() {
    let (mut a, _) = pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            output_group_flush: true,
            ..config(16384, 1000)
        },
        u32::MAX - 1500,
    );
    a.write(&[9; 7000]).unwrap();
    let mut reservation = crate::output_reservation::OutputReservation::new();
    reservation.bytes.resize(2048, 0);
    reservation.payload.resize(8000, 0);
    let mut bytes = [0; 2048];
    let n = gso_select(&mut a, 40, &mut reservation.payload, &mut bytes).unwrap();
    let mut departure = a.last_departure.unwrap();
    let total = departure.segmentation.unwrap().payload_len;
    assert_eq!(total, 4000);
    let token = reservation.token().unwrap();
    reservation.capture(
        crate::Transmit {
            connection: None,
            tx_timestamp: None,
            ipv4_options: Default::default(),
            ecn: 0,
            ip: ip(tuple()),
            len: n,
            hop_limit: 64,
            dscp: 0,
        },
        &bytes,
        token,
    );
    reservation.current.as_mut().unwrap().departure = Some(departure);
    let mut accepted = 0;
    crate::allocation_tests::fail_after(0, || {
        while accepted < total {
            let p = reservation
                .fragment(if accepted < 2000 { 1020 } else { 520 }, &mut bytes)
                .unwrap();
            let segment = wire::parse(p.ip, &bytes[..p.len]).unwrap();
            let count = segment.payload.len();
            assert_eq!(
                segment.header.sequence,
                departure.start.wrapping_add(accepted as u32)
            );
            assert_eq!(segment.header.flags & PSH != 0, accepted + count == total);
            let r = reservation.current.as_mut().unwrap();
            a.accept_reserved_output(
                50 + accepted as u64,
                &mut departure,
                r.offset,
                r.emitted_bytes,
                r.finished,
            )
            .unwrap();
            accepted += count;
            r.offset += r.emitted_bytes;
        }
    });
    assert_eq!(a.rack.counts().unacked, 1);
    assert_eq!(a.rack.packet_counts().unacked, 6);
    assert!(!a.send.pushed(0, 6999));
    assert!(a.send.pushed(6999, 1));
}

#[test]
fn actual_group_flush_prr_new_data_charges_existing_credit_once() {
    for iss in [0, u32::MAX - 4999] {
        let cfg = ConnectionConfig {
            sack: true,
            rack: true,
            prr: true,
            congestion_algorithm: CongestionAlgorithm::Cubic,
            cubic_hystart: true,
            initial_window: InitialWindow::Iw10,
            output_group_flush: true,
            ..config(65536, 1000)
        };
        let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
        let syn_bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &syn_bytes).unwrap();
        let mut peer = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
        deliver(&mut peer, &mut a, 100_000);
        deliver(&mut a, &mut peer, 100_000);
        a.write(&[0x55; 10000]).unwrap();
        for _ in 0..10 {
            packet(&mut a, 100_000);
        }
        a.write(&[7; 10000]).unwrap();
        rack_sack(&mut a, 190_000, 0, &[]);
        for (now, end) in [
            (200_000, 5000),
            (202_000, 6000),
            (204_000, 7000),
            (206_000, 8000),
            (208_000, 9000),
            (210_000, 10000),
            (212_000, 11000),
            (214_000, 12000),
        ] {
            strict_ack(&mut a, now, 0, &[(4000, end)]);
            let n = a.transmit(now, &mut [0; 2048]).unwrap();
            assert!(
                n.is_some(),
                "no output at {now}, PRR={:?}, duplicate ACKs={}",
                a.prr,
                a.duplicate_acks
            );
        }
        strict_ack(&mut a, 224_000, 1000, &[(4000, 12000)]);
        let before = a.prr.unwrap();
        assert!(before.credit() >= 2000, "{before:?}");
        let next = a.snd_nxt;
        let mut payload = [0; 8000];
        let mut bytes = [0; 2048];
        gso_select(&mut a, 224_000, &mut payload, &mut bytes).unwrap();
        let mut d = a.last_departure.unwrap();
        let s = d.segmentation.unwrap();
        assert_eq!(Seq(d.start), next);
        assert!(s.payload_len >= 2000);
        assert!(s.payload_len as u32 <= before.credit());
        assert_ne!(s.terminal_flags & PSH, 0);
        let selected = a.prr.unwrap();
        assert_eq!(selected.counters().0, before.counters().0);
        assert_eq!(selected.counters().1, before.counters().1);
        assert_eq!(
            selected.counters().2,
            before.counters().2 + s.payload_len as u64
        );
        assert_eq!(selected.credit(), before.credit() - s.payload_len as u32);
        let counters = selected.counters();
        for offset in (0..s.payload_len).step_by(s.segment_payload_len) {
            a.accept_reserved_output(
                224_100 + offset as u64,
                &mut d,
                offset,
                s.segment_payload_len,
                offset + s.segment_payload_len == s.payload_len,
            )
            .unwrap();
            assert_eq!(a.prr.unwrap().counters(), counters);
        }
        // This is a new-data group, not repair coalescing or delivery credit.
        assert!(
            !a.send
                .pushed(next.distance_from(a.send_base) as usize, s.payload_len)
        );
        assert_eq!(a.snd_nxt, next.wrapping_add(s.payload_len as u32));
    }
    let mut a = rack_flight(0);
    a.config.output_group_flush = true;
    strict_ack(&mut a, 200_000, 0, &[(7000, 10000)]);
    gso_select(&mut a, 200_000, &mut [0; 8000], &mut [0; 2048]).unwrap();
    assert!(!a.last_departure.unwrap().fresh_data);
    assert_eq!(Seq(a.last_departure.unwrap().start), a.snd_una);
    assert!(a.last_departure.unwrap().segmentation.is_none());
}

#[test]
fn actual_group_flush_singleton_distinguishes_startup_and_reduced_window() {
    for reduced in [false, true] {
        let (mut a, _) = pair(
            ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                congestion_algorithm: CongestionAlgorithm::Cubic,
                output_group_flush: true,
                ..config(16384, 1000)
            },
            0,
        );
        if reduced {
            // Model the completed CC response to a ten-MSS flight; byte
            // transmission/credit behavior is tested by the full PRR trace.
            assert!(a.congestion.on_sack_recovery(a.snd_una, 10000, a.snd_nxt));
            a.congestion.complete_prr();
            a.congestion.cancel_sack_recovery();
            assert_eq!(a.congestion.ssthresh(), 7000);
        } else {
            a.congestion.limit_restart(7000);
        }
        a.write(&[7; 10000]).unwrap();
        let mut payload = [0; 8000];
        let mut bytes = [0; 2048];
        for expected in [3000, 3000, 1000] {
            let n = gso_select(&mut a, 50, &mut payload, &mut bytes).unwrap();
            let mut d = a.last_departure.unwrap();
            assert_eq!(d.payload, expected);
            if expected > 1000 {
                assert_ne!(d.segmentation.unwrap().terminal_flags & PSH, 0);
            } else {
                assert!(d.segmentation.is_none());
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes[..n]).unwrap().header.flags & PSH != 0,
                    !reduced
                );
            }
            for offset in (0..expected).step_by(1000) {
                a.accept_reserved_output(50, &mut d, offset, 1000, offset + 1000 == expected)
                    .unwrap();
            }
        }
        assert_eq!(a.flight(), 7000);
        // Startup's existing explicit window flush may retain its endpoint;
        // transient aggregation hints must not create any other SEND boundary.
        assert!(!a.send.pushed(0, 6999));
        assert_eq!(a.send.pushed(6999, 1), !reduced);
        assert!(!a.send.pushed(7000, 2999));
        assert!(a.send.pushed(9999, 1));
    }
}

#[test]
fn actual_group_flush_adapts_to_rtt_without_enabling_pacing() {
    for scale in [1, 1000] {
        for (rtt_us, expected_group) in [(100, 4000), (100000, 2000)] {
            let timebase = CallerTimebase {
                units_per_second: 1_000_000 * scale,
                ..CallerTimebase::default()
            };
            let (mut a, _) = pair(
                ConnectionConfig {
                    initial_window: InitialWindow::Iw10,
                    output_group_flush: true,
                    timebase,
                    ..config(16384, 1000)
                },
                0,
            );
            a.rtt = RttEstimator::with_timebase(a.config.rto_min_us, timebase);
            a.rtt.sample(timebase.ticks_from_us(rtt_us));
            assert!(!a.pacing_enabled());
            a.write(&[7; 7000]).unwrap();
            gso_select(&mut a, 40, &mut [0; 8000], &mut [0; 2048]).unwrap();
            assert_eq!(
                a.last_departure.unwrap().segmentation.unwrap().payload_len,
                expected_group
            );
            assert!(!a.pacing_enabled());
            assert!(!a.send.pushed(0, 6999));
            assert!(a.send.pushed(6999, 1));
        }
    }
}

#[test]
fn fresh_local_rejection_restores_sequence_push_and_denies_ack_of_unsent_bytes() {
    for scale in [1, 1000] {
        for iss in [0, u32::MAX - 50] {
            let mut cfg = config(4096, 100);
            cfg.timebase.units_per_second = 1_000_000 * scale;
            let (mut a, _) = pair(cfg, iss);
            a.set_application_timeout(Some(3_000_000)).unwrap();
            a.write_with_push(&[7; 250], true).unwrap();
            let una = a.snd_una;
            let cwnd = a.congestion.cwnd();
            let mut bytes = [0; 2048];
            a.transmit_selected(40, &mut bytes, true).unwrap().unwrap();
            assert_eq!(a.snd_nxt, una.wrapping_add(100));
            assert_eq!(a.transport_info().unacked, 0);
            assert!(!a.send.pushed(0, 249));
            assert!(a.cancel_reserved_resource(50).unwrap());
            assert_eq!(a.snd_nxt, una);
            assert_eq!(a.rack.counts().unacked, 0);
            assert_eq!(a.notsent_bytes(), 250);
            assert_eq!(a.congestion.cwnd(), cwnd);
            assert!(a.rto_deadline.is_none());
            let next = a.receive.next();
            inject(&mut a, 60, next, una.wrapping_add(100), ACK, 4096, &[]);
            assert_eq!(a.snd_una, una);
            assert_eq!(a.send.len(), 250);
            let retry = a.local_resource.unwrap().retry_at.unwrap();
            assert!(
                a.transmit_selected(retry - 1, &mut bytes, true)
                    .unwrap()
                    .is_none()
            );
            a.timeout(retry).unwrap();
            assert_eq!(a.resource_probes, 1);
            assert_eq!(a.application_deadline(), Some(retry + 3_000_000 * scale));
            a.transmit_selected(retry, &mut bytes, true)
                .unwrap()
                .unwrap();
            let mut departure = a.last_departure.unwrap();
            assert_eq!(Seq(departure.start), una);
            a.accept_reserved_output(retry, &mut departure, 0, 50, false)
                .unwrap();
            assert_eq!(a.transport_info().unacked, 1);
            assert!(!a.cancel_reserved_resource(retry).unwrap());
            a.accept_reserved_output(retry, &mut departure, 50, 50, true)
                .unwrap();
            assert!(a.local_resource.is_none());
            assert_eq!(a.application_deadline(), Some(retry + 3_000_000 * scale));
            assert_eq!(a.transport_info().unacked, 2);
            inject(
                &mut a,
                retry + 10,
                next,
                una.wrapping_add(100),
                ACK,
                4096,
                &[],
            );
            assert_eq!(a.snd_una, una.wrapping_add(100));
            assert_eq!(a.send.len(), 150);
            assert_eq!(a.resource_probes, 0);
            assert_eq!(a.consecutive_timeouts, 0);
            assert!(!a.send.pushed(0, 149));
            assert!(a.send.pushed(149, 1));
        }
    }
}

#[test]
fn late_fresh_rejection_cannot_restart_an_expired_application_deadline() {
    let (mut a, _) = pair(config(4096, 100), 0);
    a.set_application_timeout(Some(100)).unwrap();
    a.write(&[7; 250]).unwrap();
    a.transmit_selected(40, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    assert!(a.cancel_reserved_resource(200).unwrap());
    assert_eq!(a.state, State::Closed);
    assert_eq!(a.reason, Some(CloseReason::TimedOut));
    assert!(a.local_resource.is_none());
    assert_eq!(a.notsent_bytes(), 250);
    assert_eq!(a.transport_info().unacked, 0);
    assert_eq!(a.resource_probes, 0);
    assert_eq!(a.consecutive_timeouts, 0);
}

// GSO-selects `a`'s output at `now` and checks that each segment its
// reservation emits is what `scalar`, in the same state, sends then.
fn gso_matches_scalar(
    a: &mut Connection,
    scalar: &mut Connection,
    now: Instant,
) -> crate::TransmitSegmentation {
    use crate::output_reservation::OutputReservation;
    let mut reservation = OutputReservation::new();
    reservation.bytes.resize(2048, 0);
    reservation.payload.resize(4000, 0);
    let mut bytes = [0; 2048];
    let n = a
        .transmit_selected_with_gso(
            now,
            &mut bytes,
            true,
            Some(crate::output_reservation::GsoBuffer {
                limits: crate::GsoLimits {
                    max_bytes: 4000,
                    max_segments: 16,
                },
                payload: &mut reservation.payload,
            }),
        )
        .unwrap()
        .unwrap();
    let departure = a.last_departure.unwrap();
    let s = departure.segmentation.unwrap();
    let token = reservation.token().unwrap();
    reservation.capture(
        crate::Transmit {
            connection: None,
            tx_timestamp: None,
            ipv4_options: Default::default(),
            ecn: 0,
            ip: ip(tuple()),
            len: n,
            hop_limit: 64,
            dscp: 0,
        },
        &bytes,
        token,
    );
    reservation.current.as_mut().unwrap().departure = Some(departure);
    let limit = a.path_payload_limit();
    while reservation.current.as_ref().unwrap().offset < s.payload_len {
        let p = reservation.fragment(limit, &mut bytes).unwrap();
        let mut expected = [0; 2048];
        let n = scalar.transmit(now, &mut expected).unwrap().unwrap();
        assert_eq!(&bytes[..p.len], &expected[..n]);
        let r = reservation.current.as_mut().unwrap();
        r.offset += r.emitted_bytes;
    }
    s
}

#[test]
fn gso_in_recovery_ends_where_scalar_admission_does() {
    let cfg = ConnectionConfig {
        nagle: false,
        sack: true,
        rack: true,
        initial_window: InitialWindow::Iw10,
        ..config(4096, 100)
    };
    // PRR admits by its credit (600) while cwnd leaves 200: scalar output
    // pushes the segment that fills cwnd and goes on, so the group ends
    // with that segment.
    let (mut a, _) = pair(cfg.clone(), 0);
    let (mut scalar, _) = pair(cfg.clone(), 0);
    for c in [&mut a, &mut scalar] {
        c.write(&[1; 1000]).unwrap();
        let mut prr = Prr::new(1000, 100);
        prr.acknowledge(1000, 2000, 600, false);
        assert_eq!(prr.credit(), 600);
        c.prr = Some(prr);
        c.congestion.prr_window(200);
    }
    let s = gso_matches_scalar(&mut a, &mut scalar, 40);
    assert_eq!(s.payload_len, 200);
    assert_ne!(s.terminal_flags & PSH, 0);
    assert_eq!(gso_matches_scalar(&mut a, &mut scalar, 40).payload_len, 400);

    // SACK recovery admits a segment only with an SMSS of credit: 450
    // sends four full segments, and the 50-byte rest waits.
    let (mut a, _) = pair(cfg.clone(), 0);
    let (mut scalar, _) = pair(cfg, 0);
    for c in [&mut a, &mut scalar] {
        c.write(&[1; 450]).unwrap();
        let mut prr = Prr::new(1000, 100);
        prr.acknowledge(1000, 2000, 450, false);
        c.prr = Some(prr);
        c.sack_recovery = Some(SackRecovery {
            recovery_point: c.snd_nxt,
            high_rxt: c.snd_una,
            rescue_rxt: None,
            entry_pending: false,
            pipe: 0,
        });
    }
    assert_eq!(gso_matches_scalar(&mut a, &mut scalar, 40).payload_len, 400);
    assert_eq!(scalar.transmit(40, &mut [0; 2048]).unwrap(), None);
    assert_eq!(a.transmit(40, &mut [0; 2048]).unwrap(), None);
}

// An ECN pause withholds data until its deadline (count is zero before it);
// from the deadline on, before the timer clears it, a group sends what
// scalar selection does.
#[test]
fn gso_after_an_expired_ecn_pause() {
    let cfg = ConnectionConfig {
        nagle: false,
        initial_window: InitialWindow::Iw10,
        ..config(4096, 100)
    };
    let (mut a, _) = pair(cfg.clone(), 0);
    let (mut scalar, _) = pair(cfg, 0);
    for c in [&mut a, &mut scalar] {
        c.write(&[1; 450]).unwrap();
        c.ecn_pause = Some(40);
    }
    let mut payload = [0; 1000];
    assert_eq!(gso_select(&mut a, 39, &mut payload, &mut [0; 2048]), None);
    assert_eq!(scalar.transmit(39, &mut [0; 2048]).unwrap(), None);
    let s = gso_matches_scalar(&mut a, &mut scalar, 40);
    assert_eq!((s.payload_len, s.segment_payload_len), (450, 100));
    assert_eq!(a.ecn_pause, Some(40));
}
