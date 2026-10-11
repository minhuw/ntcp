use super::*;

fn client(iss: u32, size: usize) -> Connection {
    let mut cfg = config(8192, 536);
    cfg.timestamps = true;
    cfg.sack = true;
    let mut a = Connection::active(tuple(), cfg, iss, 0).unwrap();
    let mut cache = crate::fast_open::FastOpen::new().unwrap();
    cache.learn(
        0,
        tuple().local.ip(),
        tuple().remote.ip(),
        wire::FastOpenCookie::new(&[7; 8]).unwrap(),
        536,
    );
    let cached = cache.get(0, 100, tuple().local.ip(), tuple().remote.ip());
    assert_eq!(a.prepare_fast_open(cached, &vec![42; size]).unwrap(), size);
    a
}

fn synack(a: &mut Connection, acked: u32, now: u64) {
    let options = wire::Options {
        mss: Some(536),
        sack_permitted: true,
        timestamps: Some((0, a.timestamp_value(0))),
        fast_open: Some(wire::FastOpenCookie::new(&[8; 8]).unwrap()),
        ..Default::default()
    };
    let segment = wire::Segment {
        header: wire::Header {
            source_port: tuple().remote.port(),
            destination_port: tuple().local.port(),
            sequence: 999,
            acknowledgment: a.iss.wrapping_add(1 + acked).0,
            flags: SYN | ACK,
            window: 8192,
            urgent_pointer: 0,
        },
        options,
        raw_options: &[],
        payload: &[],
    };
    a.input(now, &segment).unwrap();
}

#[test]
fn syn_data_ack_bounds_wrap_partial_retry_and_flush() {
    for iss in [100, u32::MAX - 4] {
        for acked in [0, 3, 12] {
            let mut a = client(iss, 12);
            assert_eq!(a.transmit(0, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!(a.snd_nxt, a.iss);
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(syn.header.sequence, iss);
            assert_eq!(syn.payload, &[42; 12]);
            assert_eq!(syn.header.flags & PSH, 0);
            assert_eq!(a.flight(), 13);
            assert_eq!(a.data_flight(), 12);
            assert_eq!(
                a.last_output_range,
                Some(TxStreamRange { start: 0, end: 12 })
            );
            assert_eq!(a.flush().unwrap(), 0); // On-wire bytes cannot be discarded.
            synack(&mut a, acked, 1000);
            assert_eq!(a.state(), State::Established);
            assert_eq!(a.acknowledged, acked as u64);
            assert_eq!(a.send.len(), 12 - acked as usize);
            assert_eq!(a.data_flight(), 12 - acked);
            let bytes = packet(&mut a, 1000);
            let repair = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(repair.header.flags & SYN, 0);
            assert_eq!(repair.payload.len(), 12 - acked as usize);
            assert_eq!(repair.header.flags & PSH != 0, acked != 12);
            if acked != 12 {
                assert_eq!(repair.header.sequence, iss.wrapping_add(1 + acked));
                assert_eq!(
                    a.last_output_range,
                    Some(TxStreamRange {
                        start: acked as u64,
                        end: 12
                    })
                );
                assert!(a.sample.is_none());
            }
        }
        let mut a = client(iss, 12);
        packet(&mut a, 0);
        synack(&mut a, 13, 1000);
        assert_eq!(a.state(), State::SynSent);
        assert_eq!(a.acknowledged, 0);
        assert!(a.fast_open_learned.is_none());
        assert_eq!(a.send.len(), 12);
    }
}

#[test]
fn timeout_bare_syn_retains_data_and_karn() {
    let mut a = client(u32::MAX - 2, 12);
    packet(&mut a, 0);
    let timeout = a.next_deadline().unwrap();
    a.timeout(timeout).unwrap();
    let bytes = packet(&mut a, timeout);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(syn.header.flags & SYN, SYN);
    assert!(syn.payload.is_empty());
    assert!(syn.options.fast_open.is_none());
    assert_eq!(a.send.len(), 12);
    assert!(a.sample.is_none());
    synack(&mut a, 0, timeout + 1000);
    let bytes = packet(&mut a, timeout + 1000);
    let repair = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(repair.payload, &[42; 12]);
    assert_ne!(repair.header.flags & PSH, 0);
    assert_eq!(repair.header.sequence, a.iss.wrapping_add(1).0);
}

#[test]
fn reserved_syn_exact_range_and_acceptance_rtt() {
    let mut a = client(100, 12);
    let mut bytes = [0; 2048];
    a.transmit_selected(0, &mut bytes, true).unwrap().unwrap();
    let mut departure = a.last_departure.unwrap();
    assert!(departure.syn && departure.stream);
    assert_eq!(departure.start, 100);
    a.accept_reserved_output(10_000, &mut departure, 0, 12, true)
        .unwrap();
    assert_eq!(a.rack.head_transmission(Seq(101)).unwrap().0, Seq(113));
    synack(&mut a, 12, 30_000);
    assert_eq!(a.rtt.srtt(), Some(20_000));
    assert_eq!(a.acknowledged, 12);
}

#[test]
fn option_lengths_small_path_and_timestamp_credit() {
    for len in [4, 6, 8, 10, 12, 14, 16] {
        let mut a = client(100, 0);
        let mut cache = crate::fast_open::FastOpen::new().unwrap();
        cache.learn(
            0,
            tuple().local.ip(),
            tuple().remote.ip(),
            wire::FastOpenCookie::new(&[1; 16][..len]).unwrap(),
            536,
        );
        a.prepare_fast_open(
            cache.get(0, 100, tuple().local.ip(), tuple().remote.ip()),
            &[1; 496],
        )
        .unwrap();
        let bytes = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(syn.options.fast_open.unwrap().as_bytes().len(), len);
        assert!(syn.options.sack_permitted);
        assert!(syn.raw_options.len() + syn.payload.len() <= 536);
    }
    let mut a = client(100, 12);
    a.config.timestamp_bytes_per_tick = 1;
    let bytes = packet(&mut a, 0);
    assert!(wire::parse(ip(tuple()), &bytes).unwrap().payload.is_empty());
    assert_eq!(a.send.len(), 12);
    assert_eq!(a.snd_nxt, Seq(101));
    let mut a = client(100, 12);
    a.config.send_ip_payload_limit = 44;
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    assert!(syn.payload.is_empty());
    assert!(syn.options.fast_open.is_none()); // Never emit cookieless early data.
    assert!(bytes.len() <= 44);
    assert_eq!(a.send.len(), 12);
}

#[test]
fn simultaneous_open_acknowledges_syn_data_without_early_passive_delivery() {
    let mut a = client(u32::MAX - 4, 12);
    let mut b = Connection::active(reverse(tuple()), a.config.clone(), 900, 0).unwrap();
    let a_syn = packet(&mut a, 0);
    let b_syn = packet(&mut b, 0);
    a.input(10, &wire::parse(ip(b.tuple()), &b_syn).unwrap())
        .unwrap();
    b.input(10, &wire::parse(ip(a.tuple()), &a_syn).unwrap())
        .unwrap();
    assert_eq!(b.read(&mut [0; 32]), Err(Error::WouldBlock));
    let a_synack = packet(&mut a, 20);
    let b_synack = packet(&mut b, 20);
    a.input(30, &wire::parse(ip(b.tuple()), &b_synack).unwrap())
        .unwrap();
    b.input(30, &wire::parse(ip(a.tuple()), &a_synack).unwrap())
        .unwrap();
    assert_eq!(a.state, State::Established);
    assert_eq!(b.state, State::Established);
    assert_eq!(a.acknowledged, 12);
    assert_eq!(b.read(&mut [0; 32]).unwrap(), 12);
}

fn selected_packet(a: &mut Connection, now: &mut u64, reserved: bool) -> Option<Vec<u8>> {
    let mut bytes = vec![0; 2048];
    let len = a.transmit_selected(*now, &mut bytes, reserved).unwrap()?;
    if reserved {
        let mut departure = a.last_departure.unwrap();
        let payload = departure.payload;
        a.accept_reserved_output(*now + 10, &mut departure, 0, payload, true)
            .unwrap();
    }
    *now += 100;
    bytes.truncate(len);
    Some(bytes)
}

fn repair_obeys_negotiated_window(reserved: bool) {
    for iss in [100, u32::MAX - 100] {
        for acked in [0, 13] {
            let mut a = client(iss, 496);
            assert_eq!(a.config.initial_window, InitialWindow::Rfc5681);
            let mut now = 0;
            selected_packet(&mut a, &mut now, reserved).unwrap();
            let synack = wire::Segment {
                header: wire::Header {
                    source_port: tuple().remote.port(),
                    destination_port: tuple().local.port(),
                    sequence: 999,
                    acknowledgment: iss.wrapping_add(1 + acked),
                    flags: SYN | ACK,
                    window: 8192,
                    urgent_pointer: 0,
                },
                options: wire::Options {
                    mss: Some(64),
                    timestamps: Some((0, a.timestamp_value(0))),
                    sack_permitted: true,
                    ..wire::Options::default()
                },
                raw_options: &[],
                payload: &[],
            };
            a.input(1000, &synack).unwrap();
            assert_eq!(a.mss, 52);
            assert_eq!(a.congestion.cwnd(), 208);
            now = 2000;
            let mut sent = 0;
            while let Some(bytes) = selected_packet(&mut a, &mut now, reserved) {
                let p = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(p.header.sequence, iss.wrapping_add(1 + acked + sent));
                sent += p.payload.len() as u32;
            }
            assert_eq!(sent, 208);
            assert_eq!(
                a.fast_open_retry,
                Some((
                    Seq(iss.wrapping_add(1 + acked + 208)),
                    Seq(iss.wrapping_add(497))
                ))
            );
            assert_eq!(a.data_flight(), 496 - acked);
            let seq = a.receive.next();
            let ack = a.snd_una.wrapping_add(52);
            inject_sack(&mut a, now, seq, ack, ACK, 8192, &[], &[]);
            now += 100;
            let credit = a.congestion.cwnd().saturating_sub(156);
            let mut resumed = 0;
            while let Some(bytes) = selected_packet(&mut a, &mut now, reserved) {
                let p = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(
                    p.header.sequence,
                    iss.wrapping_add(1 + acked + 208 + resumed)
                );
                resumed += p.payload.len() as u32;
            }
            assert_eq!(resumed, credit.min(496 - acked - 208));
            assert!(resumed > 0);
            assert!(a.sample.is_none()); // Repair does not create a Karn-ambiguous sample.
        }
    }
}

#[test]
fn scalar_fast_open_repair_stops_at_negotiated_cwnd() {
    repair_obeys_negotiated_window(false);
}

#[test]
fn reserved_fast_open_repair_stops_at_negotiated_cwnd() {
    repair_obeys_negotiated_window(true);
}

#[test]
fn rejected_syn_data_retry_keeps_timestamp_reset_and_conflicting_syn_guards() {
    for (sequence, flags, timestamp, state, retry) in [
        (100, SYN, Some((10, 0)), State::SynReceived, true),
        (100, SYN, Some((9, 0)), State::SynReceived, false),
        (100, SYN, None, State::SynReceived, false),
        (102, SYN, Some((10, 0)), State::Closed, false),
        (101, SYN | RST, None, State::Closed, false),
    ] {
        let mut cfg = config(8192, 536);
        cfg.timestamps = true;
        let initial = wire::Segment {
            header: wire::Header {
                source_port: tuple().local.port(),
                destination_port: tuple().remote.port(),
                sequence: 100,
                acknowledgment: 0,
                flags: SYN,
                window: 8192,
                urgent_pointer: 0,
            },
            options: wire::Options {
                timestamps: Some((10, 0)),
                ..wire::Options::default()
            },
            raw_options: &[],
            payload: &[], // Endpoint rejected the initial SYN data.
        };
        let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &initial).unwrap();
        packet(&mut b, 10);
        let duplicate = wire::Segment {
            header: wire::Header {
                sequence,
                flags,
                ..initial.header
            },
            options: wire::Options {
                timestamps: timestamp,
                ..initial.options
            },
            raw_options: &[],
            payload: b"abc",
        };
        b.input(20, &duplicate).unwrap();
        assert_eq!(b.state, state);
        assert_eq!(b.syn_pending, retry);
        assert_eq!(b.receive.next(), Seq(101));
        assert_eq!(b.receive_used, 0);
    }
}

#[test]
fn ordinary_syn_data_remains_hidden_after_terminal_reset() {
    for flags in [RST, SYN] {
        let initial = wire::Segment {
            header: wire::Header {
                source_port: tuple().local.port(),
                destination_port: tuple().remote.port(),
                sequence: 100,
                acknowledgment: 0,
                flags: SYN,
                window: 8192,
                urgent_pointer: 0,
            },
            options: wire::Options::default(),
            raw_options: &[],
            payload: b"abc",
        };
        let mut b =
            Connection::passive(reverse(tuple()), config(8192, 536), 900, 0, &initial).unwrap();
        packet(&mut b, 10);
        assert_eq!(b.receive.readable(), 3);
        assert_eq!(b.read(&mut [0; 3]), Err(Error::WouldBlock));
        let reset = wire::Segment {
            header: wire::Header {
                sequence: 104,
                flags,
                ..initial.header
            },
            payload: &[],
            ..initial
        };
        b.input(20, &reset).unwrap();
        assert_eq!(b.state(), State::Closed);
        assert!(b.take_events().is_empty());
        assert_eq!(b.terminal_readable_bytes(), 0);
        assert_eq!(b.peek_terminal(&mut [0; 3]), Ok(0));
        assert_eq!(b.read_terminal(&mut [0; 3]), Ok(0));
    }
}

#[test]
fn automatic_tfo_push_must_not_mark_flushed_replacement() {
    for iss in [100, u32::MAX - 4] {
        for retained in [0, 6] {
            let mut a = client(iss, 12);
            // No offered window discards all; a clipped SYN retains its flight.
            if retained != 0 {
                a.config.timestamp_bytes_per_tick = 7;
                let bytes = packet(&mut a, 0);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().payload.len(),
                    retained
                );
                a.config.timestamp_bytes_per_tick = 1 << 20;
            }
            assert_eq!(a.flush(), Ok(12 - retained));
            assert_eq!(a.write_with_push(b"replacement!", false), Ok(12));
            if retained == 0 {
                let bytes = packet(&mut a, 0);
                let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(syn.payload, b"replacement!");
                assert_eq!(syn.header.flags & PSH, 0);
            }
            synack(&mut a, 0, 1000);
            assert!(!a.send.pushed(0, a.send.len()));
            let bytes = packet(&mut a, 1000);
            let repair = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                repair.payload,
                if retained == 0 {
                    &b"replacement!"[..]
                } else {
                    &[42; 6]
                }
            );
            assert_eq!(repair.header.flags & PSH, 0);
        }
    }
}

#[test]
fn deferred_tfo_push_stays_at_original_end_after_ack_and_later_writes() {
    for iss in [100, u32::MAX - 4] {
        for reserved in [false, true] {
            for acked in [0, 3, 12] {
                let mut a = client(iss, 12);
                a.config.nagle = false;
                a.write_with_push(b"later", false).unwrap();
                let mut now = 0;
                let bytes = selected_packet(&mut a, &mut now, reserved).unwrap();
                let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(syn.payload, &[42; 12]);
                assert_eq!(syn.header.flags & PSH, 0);
                synack(&mut a, acked, 1000);
                assert!(!a.deferred_tfo_push);
                let remaining = 12 - acked as usize;
                for offset in 0..a.send.len() {
                    assert_eq!(
                        a.send.pushed(offset, 1),
                        remaining != 0 && offset + 1 == remaining
                    );
                }
                now = 2000;
                let bytes = selected_packet(&mut a, &mut now, reserved).unwrap();
                let output = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(output.header.flags & PSH != 0, remaining != 0);
                assert_eq!(output.payload, &[42; 12][..remaining]);
                if remaining == 0 {
                    now = a.sws_deadline.unwrap();
                    a.timeout(now).unwrap();
                    let bytes = selected_packet(&mut a, &mut now, reserved).unwrap();
                    let later = wire::parse(ip(tuple()), &bytes).unwrap();
                    assert_eq!(later.payload, b"later");
                    assert_eq!(later.header.flags & PSH, 0);
                }
            }
        }
    }
}

#[test]
fn deferred_tfo_push_survives_clipping_eor_resize_and_flush_of_only_later_data() {
    for iss in [100, u32::MAX - 4] {
        for clipped in [false, true] {
            let mut a = client(iss, 12);
            a.config.nagle = false;
            a.finish_send(12, true, true, false); // EOR alone must not PUSH the SYN.
            if clipped {
                a.config.timestamp_bytes_per_tick = 7;
            }
            let bytes = packet(&mut a, 0);
            let syn = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(syn.payload.len(), if clipped { 6 } else { 12 });
            assert_eq!(syn.header.flags & PSH, 0);
            a.config.timestamp_bytes_per_tick = 1 << 20;
            a.write_with_push(b"later", false).unwrap();
            // Keep the original endpoint even when the SYN was clipped.
            a.snd_wnd = 13;
            assert_eq!(a.flush(), Ok(5));
            a.write_with_push(b"after", false).unwrap();
            a.set_buffer_capacities(16384, 8192, usize::MAX).unwrap();
            a.set_buffer_capacities(8, 8192, usize::MAX).unwrap(); // Limit shrink preserves bytes.
            synack(&mut a, 3, 1000);
            assert_eq!(a.send.record_len(0, a.send.len()), 9);
            assert!(a.send.pushed(8, 1));
            assert!(!a.send.pushed(9, 5));
            let bytes = packet(&mut a, 1000);
            let repair = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(repair.payload.len(), if clipped { 3 } else { 9 });
            assert_eq!(repair.header.flags & PSH != 0, !clipped);
            if clipped {
                let bytes = packet(&mut a, 2000);
                let suffix = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(suffix.payload, &[42; 6]);
                assert_ne!(suffix.header.flags & PSH, 0);
            }
        }
    }
}

#[test]
fn deferred_tfo_push_simultaneous_open_and_terminal_cleanup() {
    for iss in [100, u32::MAX - 4] {
        for acked in [0, 3, 12] {
            let mut a = client(iss, 12);
            packet(&mut a, 0);
            let syn = wire::Segment {
                header: wire::Header {
                    source_port: tuple().remote.port(),
                    destination_port: tuple().local.port(),
                    sequence: 999,
                    acknowledgment: 0,
                    flags: SYN,
                    window: 8192,
                    urgent_pointer: 0,
                },
                options: wire::Options::default(),
                raw_options: &[],
                payload: &[],
            };
            a.input(100, &syn).unwrap();
            assert_eq!(a.state(), State::SynReceived);
            packet(&mut a, 200);
            synack(&mut a, acked, 1000);
            assert_eq!(a.state(), State::Established);
            assert!(!a.deferred_tfo_push);
            assert_eq!(a.send.pushed(0, a.send.len()), acked != 12);
            let bytes = packet(&mut a, 1000);
            let repair = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(repair.payload, &[42; 12][acked as usize..]);
            assert_eq!(repair.header.flags & PSH != 0, acked != 12);
        }
        let mut a = client(iss, 12);
        assert!(a.deferred_tfo_push);
        a.terminal(CloseReason::Reset);
        assert!(!a.deferred_tfo_push);
        assert_eq!(a.state(), State::Closed);
        assert!(!client(iss, 0).deferred_tfo_push);
    }
}
