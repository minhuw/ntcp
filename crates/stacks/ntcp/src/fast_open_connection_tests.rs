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
fn simultaneous_open_rejects_recognized_syn_data_until_retransmitted() {
    for iss in [1234, u32::MAX - 4] {
        let mut a = client(iss, 496);
        let mut b = Connection::active(reverse(tuple()), a.config.clone(), 900, 0).unwrap();
        let a_syn = packet(&mut a, 0);
        let b_syn = packet(&mut b, 0);
        a.input(10, &wire::parse(ip(b.tuple()), &b_syn).unwrap())
            .unwrap();
        b.input(10, &wire::parse(ip(a.tuple()), &a_syn).unwrap())
            .unwrap();
        assert_eq!(b.read(&mut [0; 512]), Err(Error::WouldBlock));
        assert_eq!(b.receive_used, 0);
        let a_synack = packet(&mut a, 20);
        let b_synack = packet(&mut b, 20);
        // RFC 7413 §4.2.2 applies the same receive admission to simultaneous open.
        assert_eq!(
            wire::parse(ip(b.tuple()), &b_synack)
                .unwrap()
                .header
                .acknowledgment,
            iss.wrapping_add(1)
        );
        // A duplicate crossing SYN cannot sneak the rejected data into receive.
        b.input(25, &wire::parse(ip(a.tuple()), &a_syn).unwrap())
            .unwrap();
        assert_eq!(b.receive_used, 0);
        a.input(30, &wire::parse(ip(b.tuple()), &b_synack).unwrap())
            .unwrap();
        b.input(30, &wire::parse(ip(a.tuple()), &a_synack).unwrap())
            .unwrap();
        assert_eq!(a.state, State::Established);
        assert_eq!(b.state, State::Established);
        assert_eq!(a.acknowledged, 0);
        assert_eq!(b.read(&mut [0; 512]), Err(Error::WouldBlock));
        let retry = packet(&mut a, 40);
        let retry = wire::parse(ip(a.tuple()), &retry).unwrap();
        assert_eq!(retry.header.sequence, iss.wrapping_add(1));
        assert_eq!(retry.payload, &[42; 496]);
        b.input(50, &retry).unwrap();
        let mut out = [0; 512];
        assert_eq!(b.read(&mut out), Ok(496));
        assert_eq!(&out[..496], &[42; 496]);
        b.input(60, &retry).unwrap();
        assert_eq!(b.read(&mut out), Err(Error::WouldBlock));
    }
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
        assert_eq!(b.receive.readable(), 0);
        assert_eq!(b.read(&mut [0; 3]), Err(Error::WouldBlock));
        let reset = wire::Segment {
            header: wire::Header {
                sequence: 101,
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

#[test]
fn passive_repair_ack_provenance_and_handshake_latch() {
    for iss in [100, u32::MAX] {
        for payload in [b"".as_slice(), b"early"] {
            for early in [false, true] {
                let mut a = client(iss, 5);
                let bytes = packet(&mut a, 0);
                let mut syn = wire::parse(ip(tuple()), &bytes).unwrap();
                syn.payload = payload;
                let mut b = Connection::passive_with_receive(
                    reverse(tuple()),
                    config(8192, 536),
                    900,
                    0,
                    &syn,
                    early,
                    &mut None,
                    RxTimestamps::default(),
                    RxPacketTimestamps::default(),
                )
                .unwrap();
                b.passive_fast_open(None, early);
                assert!(!b.transport_info().syn_data_acked);
                let bytes = packet(&mut b, 0);
                let response = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
                assert_eq!(
                    response.header.acknowledgment,
                    iss.wrapping_add(1 + if early { payload.len() as u32 } else { 0 })
                );
                let eligible = early && !payload.is_empty();
                assert_eq!(b.transport_info().syn_data_acked, eligible);
                let ack = wire::Segment {
                    header: wire::Header {
                        sequence: response.header.acknowledgment,
                        acknowledgment: 901,
                        flags: ACK,
                        ..syn.header
                    },
                    options: wire::Options::default(),
                    raw_options: &[],
                    payload: &[],
                };
                b.input(1, &ack).unwrap();
                assert_eq!(b.state(), State::Established);
                if !payload.is_empty() {
                    let mut out = [0; 5];
                    assert_eq!(b.read(&mut out), Ok(payload.len()));
                    assert_eq!(&out[..payload.len()], payload);
                }
                assert_eq!(b.transport_info().syn_data_acked, eligible);
                b.abort();
                assert_eq!(b.transport_info().syn_data_acked, eligible);
            }
        }
    }
}

#[test]
fn recognized_crossing_syn_admission_preserves_synack_and_ordinary_data() {
    for sequence in [1234, u32::MAX - 4] {
        for cookie in [
            None,
            Some(wire::FastOpenCookie::request()),
            Some(wire::FastOpenCookie::new(&[7; 8]).unwrap()),
        ] {
            for ack in [false, true] {
                for controls in [0, FIN | PSH | URG] {
                    let mut a = client(100, 12); // Has an outgoing cookie, not receive authorization.
                    packet(&mut a, 0);
                    let fallback = !ack && cookie.is_some();
                    let syn = wire::Segment {
                        header: wire::Header {
                            source_port: tuple().remote.port(),
                            destination_port: tuple().local.port(),
                            sequence,
                            acknowledgment: 101,
                            flags: SYN
                                | if ack { ACK } else { 0 }
                                | if fallback { controls } else { 0 },
                            window: 8192,
                            urgent_pointer: if fallback { 501 } else { 0 },
                        },
                        options: wire::Options {
                            mss: Some(536),
                            window_scale: Some(2),
                            sack_permitted: true,
                            timestamps: Some((7, 0)),
                            fast_open: cookie,
                            ..Default::default()
                        },
                        raw_options: &[],
                        payload: &[42; 500],
                    };
                    a.input(10, &syn).unwrap();
                    assert_eq!(
                        a.receive.next(),
                        Seq(sequence.wrapping_add(if ack { 501 } else { 1 }))
                    );
                    assert_eq!(a.receive_used, if fallback { 0 } else { 500 });
                    assert_eq!(a.rcv_up, None);
                    assert!(a.timestamps && a.sack_send && a.scaling);
                    assert_eq!(a.peer_scale, 2);
                    assert_eq!(a.peer_mss, 536);
                    assert_eq!(a.ts_recent, 7);
                    let reply = packet(&mut a, 20);
                    let reply = wire::parse(ip(tuple()), &reply).unwrap();
                    // Recognized crossing SYN: ACK 1235, never 1735; normal SYN-ACK data is retained.
                    assert_eq!(
                        reply.header.acknowledgment,
                        sequence.wrapping_add(if ack { 501 } else { 1 })
                    );
                    assert_eq!(
                        a.read(&mut [0; 512]),
                        if ack { Ok(500) } else { Err(Error::WouldBlock) }
                    );
                    if !ack && !fallback {
                        let final_ack = wire::Segment {
                            header: wire::Header {
                                sequence: sequence.wrapping_add(1),
                                flags: ACK,
                                ..syn.header
                            },
                            payload: &[],
                            ..syn
                        };
                        a.input(30, &final_ack).unwrap();
                        let mut retained = [0; 512];
                        assert_eq!(a.read(&mut retained), Ok(500));
                        assert_eq!(&retained[..500], &[42; 500]);
                        assert_eq!(a.read(&mut retained), Err(Error::WouldBlock));
                    }
                    if fallback {
                        assert!(!a.receive.eof());
                        let reset = wire::Segment {
                            header: wire::Header {
                                sequence: sequence.wrapping_add(1),
                                flags: RST,
                                ..syn.header
                            },
                            options: wire::Options::default(),
                            raw_options: &[],
                            payload: &[],
                        };
                        a.input(30, &reset).unwrap();
                        assert_eq!(a.state(), State::Closed);
                        assert_eq!(a.terminal_readable_bytes(), 0);
                    }
                }
            }
        }
    }
}

// The packetdrill crossing trace, with optional wrap, SACK/TS and ordinary SYN text.
fn simultaneous_syn_dsack_setup(
    irs: u32,
    sack: bool,
    timestamps: bool,
    fast_open: bool,
) -> (Connection, wire::Segment<'static>) {
    let mut cfg = config(8192, 1460);
    cfg.delayed_ack_us = 0; // Match the existing upstream-fastopen profile.
    cfg.sack = sack;
    cfg.timestamps = timestamps;
    let mut a = Connection::active(tuple(), cfg, 0, 0).unwrap();
    let mut cache = crate::fast_open::FastOpen::new().unwrap();
    cache.learn(
        0,
        tuple().local.ip(),
        tuple().remote.ip(),
        wire::FastOpenCookie::new(&[0xab, 0xcd, 0x12, 0x34]).unwrap(),
        1460,
    );
    a.prepare_fast_open(
        cache.get(0, 100, tuple().local.ip(), tuple().remote.ip()),
        &[42; 1000],
    )
    .unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(syn.header.sequence, 0);
    assert_eq!(syn.payload, &[42; 1000]);
    let mut peer = wire::Segment {
        header: wire::Header {
            source_port: tuple().remote.port(),
            destination_port: tuple().local.port(),
            sequence: irs,
            acknowledgment: 0,
            flags: SYN,
            window: 14600,
            urgent_pointer: 0,
        },
        options: wire::Options {
            mss: Some(1040),
            window_scale: Some(6),
            sack_permitted: sack,
            timestamps: timestamps.then_some((7, 0)),
            fast_open: fast_open
                .then(|| wire::FastOpenCookie::new(&[0x87, 0x65, 0x43, 0x21]).unwrap()),
            ..Default::default()
        },
        raw_options: &[],
        payload: &[43; 500],
    };
    a.input(5_000, &peer).unwrap();
    assert_eq!(a.state(), State::SynReceived);
    assert_eq!(a.read(&mut [0; 500]), Err(Error::WouldBlock));
    assert_eq!(a.receive_used, if fast_open { 0 } else { 500 });
    let bytes = packet(&mut a, 5_000);
    let reply = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!(reply.header.flags, SYN | ACK);
    assert_eq!(reply.header.sequence, 0);
    assert_eq!(reply.header.acknowledgment, irs.wrapping_add(1));
    assert!(reply.payload.is_empty());
    assert!(reply.options.fast_open.is_none());
    assert_eq!(reply.options.sack_blocks, [None; 4]);
    peer.header.flags = SYN | ACK;
    peer.header.acknowledgment = 1001;
    peer.options.mss = Some(940);
    peer.options.fast_open = Some(wire::FastOpenCookie::new(&[0x12, 0x34, 0x56, 0x78]).unwrap());
    peer.payload = &[];
    (a, peer)
}

#[test]
fn simultaneous_syn_dsack_crossing_trace_retry_wrap_and_sack_off() {
    for irs in [1234, u32::MAX] {
        for sack in [false, true] {
            for reserved in [false, true] {
                let (mut a, mut peer) = simultaneous_syn_dsack_setup(irs, sack, false, true);
                a.input(50_000, &peer).unwrap();
                assert_eq!(a.state(), State::Established);
                assert_eq!(a.acknowledged, 1000);
                assert_eq!(a.receive_used, 0);
                assert_eq!(a.read(&mut [0; 500]), Err(Error::WouldBlock));
                assert_eq!(a.peer_mss, 1040); // Completion must not renegotiate MSS.
                assert_eq!(
                    a.transmit_selected(50_000, &mut [0; 19], reserved),
                    Err(Error::OutputTooSmall)
                );
                let mut now = 50_000;
                let bytes = selected_packet(&mut a, &mut now, reserved).unwrap();
                let reply = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(reply.header.flags, ACK);
                assert_eq!(reply.header.sequence, 1001);
                assert_eq!(reply.header.acknowledgment, irs.wrapping_add(1));
                assert!(reply.payload.is_empty());
                assert_eq!(
                    reply.options.sack_blocks,
                    [sack.then_some((irs, irs.wrapping_add(1))), None, None, None]
                );
                assert_eq!(bytes.len(), if sack { 32 } else { 20 });
                assert!(selected_packet(&mut a, &mut now, reserved).is_none());
                // An unrelated output, without a new arrival, cannot repeat the report.
                a.immediate_ack();
                let bytes = selected_packet(&mut a, &mut now, reserved).unwrap();
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes)
                        .unwrap()
                        .options
                        .sack_blocks,
                    [None; 4]
                );

                // The rejected 500 bytes are delivered only on ordinary retransmission.
                peer.header.sequence = irs.wrapping_add(1);
                peer.header.acknowledgment = 1000;
                peer.header.flags = PSH | ACK;
                peer.header.window = 257;
                peer.options = wire::Options::default();
                peer.payload = &[43; 500];
                a.input(150_000, &peer).unwrap();
                let bytes = packet(&mut a, 150_000);
                let reply = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(reply.header.acknowledgment, irs.wrapping_add(501));
                assert_eq!(reply.options.sack_blocks, [None; 4]);
                let mut out = [0; 500];
                assert_eq!(a.read(&mut out), Ok(500));
                assert_eq!(out, [43; 500]);
                a.input(150_001, &peer).unwrap();
                assert_eq!(a.read(&mut out), Err(Error::WouldBlock));
                let bytes = packet(&mut a, 150_001);
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes)
                        .unwrap()
                        .options
                        .sack_blocks,
                    [
                        sack.then_some((irs.wrapping_add(1), irs.wrapping_add(501))),
                        None,
                        None,
                        None
                    ]
                );
            }
        }
    }
}

#[test]
fn simultaneous_syn_dsack_validated_completion_only() {
    for irs in [1234, u32::MAX] {
        for (seq, ack, flags, ts) in [
            (irs.wrapping_add(1), 1001, SYN | ACK, Some((7, 0))),
            (irs.wrapping_sub(1), 1001, SYN | ACK, Some((7, 0))),
            (irs, 0, SYN | ACK, Some((7, 0))),
            (irs, 1002, SYN | ACK, Some((7, 0))),
            (irs, 1001, SYN | ACK | FIN, Some((7, 0))),
            (irs, 1001, SYN | ACK | RST, Some((7, 0))),
            (irs, 1001, SYN, Some((7, 0))),
            (irs, 1001, ACK, Some((7, 0))),
            (irs, 1001, SYN | ACK, None),
            (irs, 1001, SYN | ACK, Some((6, 0))),
        ] {
            let (mut a, mut peer) = simultaneous_syn_dsack_setup(irs, true, true, true);
            peer.header.sequence = seq;
            peer.header.acknowledgment = ack;
            peer.header.flags = flags;
            peer.options.timestamps = ts;
            a.input(50_000, &peer).unwrap();
            assert_eq!(a.state(), State::SynReceived);
            assert_eq!(a.receive.next(), Seq(irs.wrapping_add(1)));
            assert_eq!(a.receive_used, 0);
            assert_eq!(a.acknowledged, 0);
            assert_eq!(a.ts_recent, 7);
            assert_eq!(a.receive.sack_blocks(4), [None; 4]);
            let mut now = 50_000;
            if let Some(bytes) = selected_packet(&mut a, &mut now, false) {
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes)
                        .unwrap()
                        .options
                        .sack_blocks,
                    [None; 4]
                );
            }
        }
        let (mut a, peer) = simultaneous_syn_dsack_setup(irs, true, true, true);
        a.sack_omit = true; // Empty receive_text must not suppress this new report.
        a.input(50_000, &peer).unwrap();
        assert_eq!(a.state(), State::Established);
        let bytes = packet(&mut a, 50_000);
        let reply = wire::parse(ip(tuple()), &bytes).unwrap();
        assert!(reply.options.timestamps.is_some());
        assert_eq!(
            reply.options.sack_blocks[0],
            Some((irs, irs.wrapping_add(1)))
        );
        // Once synchronized, even the identical SYN+ACK is only challenged.
        a.input(50_001, &peer).unwrap();
        let bytes = packet(&mut a, 50_001);
        assert_eq!(
            wire::parse(ip(tuple()), &bytes)
                .unwrap()
                .options
                .sack_blocks,
            [None; 4]
        );
    }
}

#[test]
fn simultaneous_syn_dsack_preserves_payload_report() {
    for fast_open in [false, true] {
        let (mut a, mut peer) = simultaneous_syn_dsack_setup(u32::MAX, true, false, fast_open);
        peer.payload = &[43; 500];
        a.input(50_000, &peer).unwrap();
        assert_eq!(a.state(), State::Established);
        assert_eq!(a.receive_used, 500);
        let bytes = packet(&mut a, 50_000);
        let reply = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(reply.header.acknowledgment, 500);
        assert_eq!(
            reply.options.sack_blocks,
            [(!fast_open).then_some((0, 500)), None, None, None]
        );
        let mut out = [0; 500];
        assert_eq!(a.read(&mut out), Ok(500));
        assert_eq!(out, [43; 500]);
        assert_eq!(a.read(&mut out), Err(Error::WouldBlock));
    }
}

#[test]
fn timed_out_syn_ack_rearms_residual_tfo_with_data_phase_floor() {
    for reserved in [false, true] {
        for acked in [0, 3] {
            let mut a = client(100, 12);
            let mut bytes = [0; 2048];
            for now in [0, 1_000_000] {
                if now != 0 {
                    a.timeout(now).unwrap();
                }
                let size = a
                    .transmit_selected(now, &mut bytes, reserved)
                    .unwrap()
                    .unwrap();
                let syn = wire::parse(ip(tuple()), &bytes[..size]).unwrap();
                assert_eq!(syn.payload.len(), if now == 0 { 12 } else { 0 });
                if reserved {
                    let mut departure = a.last_departure.unwrap();
                    a.accept_reserved_output(now, &mut departure, 0, syn.payload.len(), true)
                        .unwrap();
                }
            }
            assert_eq!(a.rto_deadline, Some(3_000_000));
            assert!(!a.syn_delivered);
            synack(&mut a, acked, 1_100_000);
            assert!(a.syn_delivered && a.syn_timed_out);
            assert_eq!(a.state(), State::Established);
            assert_eq!(a.data_flight(), 12 - acked);
            // accept_ack rearms this flight before establish changes handshake state.
            assert_eq!(a.rto_deadline, Some(4_100_000));
            assert_eq!(a.rto(), 3_000_000);
            assert_eq!(a.rtt.updates, 0); // Neither SYN retry nor SYN data supplies fresh RTT.
        }
    }
}

#[test]
fn tfo_two_retry_budget_keeps_exponential_syn_wait() {
    let mut a = client(100, 12);
    a.set_handshake_retransmission_limit(core::num::NonZeroU8::new(2));
    for (retry, now) in [(0, 0), (1, 1_000_000), (2, 3_000_000)] {
        if retry != 0 {
            assert_eq!(a.rto_deadline, Some(now));
            a.timeout(now - 1).unwrap();
            assert_eq!(a.transmit(now - 1, &mut [0; 2048]), Ok(None));
            a.timeout(now).unwrap();
        }
        let bytes = packet(&mut a, now);
        let syn = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_ne!(syn.header.flags & SYN, 0);
        assert_eq!(syn.payload.len(), if retry == 0 { 12 } else { 0 });
        assert_eq!(a.committed_syn_retransmissions, retry);
    }
    assert_eq!(a.rto_deadline, Some(7_000_000));
    a.timeout(6_999_999).unwrap();
    assert!(a.handshake_pending());
    a.timeout(7_000_000).unwrap();
    assert_eq!(a.reason, Some(CloseReason::TimedOut));
    assert_eq!(a.transmit(7_000_000, &mut [0; 2048]), Ok(None));
}
