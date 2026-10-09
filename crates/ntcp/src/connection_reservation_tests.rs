use super::*;

#[test]
fn reserved_nonhead_sack_retry_keeps_exhausted_prr_credit_and_recovery_state() {
    use crate::output_reservation::OutputReservation;
    for iss in [0, u32::MAX - 4999] {
        let mut a = strict_flight(iss);
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
        let token = reservation.token(None).unwrap();
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
    assert!(a.sample.is_none());

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
    a.accept_reserved_output(2_000_000, &mut d, 0, 1, true)
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
            prr_algorithm: PrrAlgorithm::Rfc9937,
            pacing: general.then_some(PacingConfig {
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
    let mut d = a.last_departure.unwrap();
    let count = d.payload;
    a.accept_reserved_output(2_000_000, &mut d, 0, count, true)
        .unwrap();
    assert!(a.sample.is_none());
    let updates = a.rtt.updates;
    let (next, end) = (a.receive.next(), a.snd_nxt);
    timestamp_input(&mut a, 2_000_100, next, end, ACK, Some((2000, echo)), b"");
    assert_eq!(a.rack.ack_sample, Some(100));
    assert_eq!(a.rtt.updates, updates + 1);
}

#[test]
fn reserved_nonhead_retry_preserves_advancing_ack_rto_restart() {
    for delay in [0, 50_000, 1_000_000] {
        let mut a = strict_flight(0);
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
