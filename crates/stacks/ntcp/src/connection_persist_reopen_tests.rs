extern crate std;

use super::*;

fn sender(iss: u32, scale: u64, nagle: bool) -> Connection {
    let cfg = ConnectionConfig {
        timestamps: true,
        sack: true,
        rack: true,
        prr: true,
        prr_pacing: false,
        pacing: None,
        tlp: true,
        initial_window: InitialWindow::Iw10,
        rto_min_us: 200_000,
        peer_max_ack_delay_us: 499_999,
        delayed_ack_us: 200_000,
        adaptive_ack: true,
        congestion_algorithm: CongestionAlgorithm::Cubic,
        nagle,
        timebase: CallerTimebase {
            units_per_second: 1_000_000 * scale,
            ..CallerTimebase::default()
        },
        ..config(65_536, 1460)
    };
    let mut a = Connection::active(tuple(), cfg, iss, 0).unwrap();
    packet(&mut a, 0);
    let metadata = ip(reverse(tuple()));
    let mut bytes = [0; 28];
    let size = wire::encode(
        metadata,
        Header {
            source_port: tuple().remote.port(),
            destination_port: tuple().local.port(),
            sequence: 900,
            acknowledgment: iss.wrapping_add(1),
            flags: SYN | ACK,
            window: 0,
            urgent_pointer: 0,
        },
        &[2, 4, 3, 232, 1, 1, 4, 2],
        &[],
        &mut bytes,
    )
    .unwrap();
    a.input(
        10_000 * scale,
        &wire::parse(metadata, &bytes[..size]).unwrap(),
    )
    .unwrap();
    packet(&mut a, 10_000 * scale);
    assert!(!a.timestamps && !a.scaling);
    assert_eq!(a.mss, 1000);
    assert_eq!(a.congestion.cwnd(), 10_000);
    a.write(&[0x55; 1000]).unwrap();
    assert_eq!(a.loss_timer, Some((LossTimer::Zwp, 210_000 * scale)));
    a
}

#[test]
fn empty_probe_reopening_orders_preserve_first_transmission() {
    for order in 0..3 {
        for iss in [0, u32::MAX] {
            for scale in [1, 1000] {
                for nagle in [false, true] {
                    let mut a = sender(iss, scale, nagle);
                    let base = Seq(iss.wrapping_add(1));
                    let now = 210_000 * scale;
                    if order != 0 {
                        a.timeout(now).unwrap();
                    }
                    if order == 2 {
                        let bytes = packet(&mut a, now);
                        let probe = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!((probe.header.sequence, probe.payload.len()), (iss, 0));
                        assert_eq!(probe.header.flags, ACK);
                        assert_eq!(a.snd_nxt, base);
                        assert_eq!(a.flight(), 0);
                        assert_eq!(a.rack.packet_counts().unacked, 0);
                        assert_eq!(a.last_output_range, None);
                        assert_eq!(a.rto_deadline, None);
                    }
                    inject(&mut a, now, Seq(901), base, ACK, 2000, &[]);
                    assert_eq!(a.transport_info().rwnd_limited_us, 200_000);
                    assert!(!a.probe_pending);
                    assert_eq!(a.persist_deadline, None);
                    let bytes = packet(&mut a, now);
                    let data = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!((data.header.sequence, data.payload.len()), (base.0, 1000));
                    assert_eq!(data.header.flags, PSH | ACK);
                    assert_eq!(a.snd_nxt, base.wrapping_add(1000));
                    assert_eq!(a.consecutive_timeouts, 0);
                    assert!(!a.congestion.in_recovery());
                }
            }
        }
    }
}

#[test]
fn empty_probe_cannot_authorize_ack_of_queued_data() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = a.snd_nxt;
        a.timeout(210_000).unwrap();
        packet(&mut a, 210_000);
        inject(
            &mut a,
            210_001,
            Seq(901),
            base.wrapping_add(1),
            ACK,
            2000,
            &[],
        );
        assert_eq!((a.snd_una, a.snd_nxt, a.snd_wnd), (base, base, 0));
        assert_eq!(a.send.len(), 1000);
        let reply = packet(&mut a, 210_001);
        assert!(wire::parse(ip(tuple()), &reply).unwrap().payload.is_empty());
        inject(&mut a, 210_002, Seq(901), base, ACK, 2000, &[]);
        let before = (a.snd_nxt, a.congestion.cwnd(), a.rto_deadline);
        assert_eq!(
            a.transmit(210_002, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!((a.snd_nxt, a.congestion.cwnd(), a.rto_deadline), before);
        let data = packet(&mut a, 210_002);
        assert_eq!(wire::parse(ip(tuple()), &data).unwrap().payload.len(), 1000);
        assert_eq!(a.congestion.cwnd(), 10_000);
    }
}

#[test]
fn empty_probe_backoff_and_history_ignore_closed_window_feedback() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = a.snd_nxt;
        let baseline = (a.rto(), a.congestion.cwnd(), a.rtt_sample_after);
        for (now, next) in [
            (210_000, 610_000),
            (610_000, 1_410_000),
            (1_410_000, 3_010_000),
        ] {
            a.timeout(now).unwrap();
            let before = (a.persist_interval, a.loss_timer);
            assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!((a.persist_interval, a.loss_timer), before);
            let bytes = packet(&mut a, now);
            let probe = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                (probe.header.sequence, probe.payload.len()),
                (base.wrapping_add(u32::MAX).0, 0)
            );
            assert_eq!(a.loss_timer, Some((LossTimer::Zwp, next)));
            inject(&mut a, now + 1, Seq(901), base, ACK, 0, &[]);
            assert_eq!(a.loss_timer, Some((LossTimer::Zwp, next)));
            assert_eq!((a.snd_una, a.snd_nxt), (base, base));
            assert_eq!((a.rto(), a.congestion.cwnd(), a.rtt_sample_after), baseline);
            assert_eq!(a.transport_info().notsent_bytes, 1000);
            assert_eq!(a.consecutive_timeouts, 0);
        }
    }
}

#[test]
fn reserved_empty_probe_timer_uses_actual_acceptance_and_not_stream_credit() {
    for iss in [0, u32::MAX] {
        for opened in [false, true] {
            let mut a = sender(iss, 1, true);
            let base = a.snd_nxt;
            a.timeout(210_000).unwrap();
            let mut out = [0; 1500];
            let n = a
                .transmit_selected(210_000, &mut out, true)
                .unwrap()
                .unwrap();
            let probe = wire::parse(ip(tuple()), &out[..n]).unwrap();
            assert!(probe.payload.is_empty());
            let mut d = a.last_departure.unwrap();
            assert!(d.persist && !d.stream && !d.rto);
            assert_eq!(a.persist_unanswered_since, None);
            let interval = a.persist_interval;
            assert_eq!(a.snd_nxt, base);
            if opened {
                inject(&mut a, 211_000, Seq(901), base, ACK, 2000, &[]);
            }
            a.accept_reserved_output(212_000, &mut d, 0, 0, true)
                .unwrap();
            assert!(!d.persist);
            assert_eq!(a.rto_deadline, None);
            assert_eq!(a.snd_nxt, base);
            assert_eq!(a.rack.packet_counts().unacked, 0);
            assert_eq!(
                a.persist_unanswered_since,
                if opened { None } else { Some(212_000) }
            );
            assert_eq!(
                a.persist_deadline,
                if opened {
                    None
                } else {
                    Some(212_000 + interval)
                }
            );
            // A repeated acceptance cannot restart the accepted control epoch.
            a.accept_reserved_output(212_001, &mut d, 0, 0, true)
                .unwrap();
            assert_eq!(
                a.persist_deadline,
                if opened {
                    None
                } else {
                    Some(212_000 + interval)
                }
            );
        }
    }
}

#[test]
fn window_probe_with_real_flight_retransmits_existing_byte() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = a.snd_nxt;
        inject(&mut a, 20_000, Seq(901), base, ACK, 2000, &[]);
        packet(&mut a, 20_000);
        let high = a.snd_nxt;
        inject(&mut a, 21_000, Seq(901), base, ACK, 0, &[]);
        let deadline = a.next_deadline().unwrap();
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        let probe = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!((probe.header.sequence, probe.payload.len()), (base.0, 1));
        assert_eq!(probe.payload, &[0x55]);
        assert_eq!((a.snd_una, a.snd_nxt), (base, high));
        assert_eq!(a.consecutive_timeouts, 0);
        assert_eq!(a.transport_info().notsent_bytes, 0);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
//= type=test
//= reason=A real receiver with full storage receives the current-sequence urgent control before the old-sequence window probe; application urgent notification advances without consuming receive space or queued sender data. The two controls consume only one persist-backoff event.
//# A TCP receiver MUST process the RST and URG fields of all incoming segments,
//# even when the receive window is zero (MUST-66).
fn empty_probe_preserves_zero_window_urgent_notification() {
    let (mut a, mut b) = pair(config(4, 4), 100);
    a.write(b"abcd").unwrap();
    deliver(&mut a, &mut b, 40);
    deliver(&mut b, &mut a, 50);
    assert_eq!(b.receive_window(), 0);
    a.write_urgent(b"e").unwrap();
    let base = a.snd_nxt;
    let deadline = a.next_deadline().unwrap();
    let interval = a.persist_interval;
    a.timeout(deadline).unwrap();
    let bytes = deliver(&mut a, &mut b, deadline);
    let notice = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!((notice.header.sequence, notice.payload.len()), (base.0, 0));
    assert_eq!(b.take_events().urgent, Some(5));
    assert_eq!(a.persist_interval, interval);
    assert!(a.probe_pending);
    let bytes = deliver(&mut a, &mut b, deadline);
    let probe = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(
        (probe.header.sequence, probe.payload.len()),
        (base.wrapping_add(u32::MAX).0, 0)
    );
    assert!(!a.probe_pending);
    assert_eq!(a.persist_interval, 2 * interval);
    deliver(&mut b, &mut a, deadline + 1);
    assert_eq!(a.snd_nxt, base);
    assert_eq!(a.transmit(deadline + 1, &mut [0; 64]), Ok(None));
}

#[test]
fn empty_probe_large_urgent_pointer_is_bounded_without_repeating_notice() {
    for reserved in [false, true] {
        let mut a = sender(u32::MAX - 500, 1, true);
        assert_eq!(a.write_urgent(&[0x77; 65_000]).unwrap(), 64_536);
        let base = a.snd_nxt;
        a.timeout(210_000).unwrap();
        let mut out = [0; 1500];
        for (index, seq) in [base, base.wrapping_add(u32::MAX)].into_iter().enumerate() {
            let n = if reserved {
                a.transmit_selected(210_000, &mut out, true)
            } else {
                a.transmit(210_000, &mut out)
            }
            .unwrap()
            .unwrap();
            let p = wire::parse(ip(tuple()), &out[..n]).unwrap();
            assert_eq!((p.header.sequence, p.payload.len()), (seq.0, 0));
            assert_eq!(p.header.urgent_pointer, u16::MAX);
            if reserved {
                let mut d = a.last_departure.unwrap();
                assert_eq!(d.persist, index == 1);
                a.accept_reserved_output(210_000, &mut d, 0, 0, true)
                    .unwrap();
            }
        }
        assert!(!a.probe_pending);
        assert_eq!(a.transmit(210_000, &mut out), Ok(None));
        assert_eq!(a.snd_nxt, base);
    }
}

mod real_peer {
    include!("connection_persist_peer_tests.rs");
}
