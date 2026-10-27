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
            assert_eq!(
                a.congestion.ack_history(),
                Some((Seq(iss), Seq(iss).wrapping_add(1 + acked)))
            );
            assert_eq!(a.state(), State::Established);
            assert_eq!(a.fast_open_negative, acked == 0);
            assert_eq!(a.transport_info().syn_data_fully_acked, acked == 12);
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
                assert!(!a.transport_info().syn_data_fully_acked);
            }
        }
        let mut a = client(iss, 12);
        packet(&mut a, 0);
        synack(&mut a, 13, 1000);
        assert_eq!(a.congestion.ack_history(), None);
        assert_eq!(a.state(), State::SynSent);
        assert_eq!(a.acknowledged, 0);
        assert!(a.fast_open_learned.is_none());
        assert!(!a.fast_open_negative);
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
            assert_eq!(a.rtt.srtt(), None); // Neither SYN retry nor SYN data supplies fresh RTT.
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

#[test]
fn fast_open_negative_requires_physical_option_and_reports_once() {
    for reserved in [false, true] {
        for option in [false, true] {
            let mut a = client(100, 12);
            if !option {
                a.config.send_ip_payload_limit = 44;
            }
            assert_eq!(
                a.transmit_selected(0, &mut [0; 19], reserved),
                Err(Error::OutputTooSmall)
            );
            assert!(!a.fast_open_attempt);
            assert!(
                !a.network_error(1, 100, NetworkError::HardUnreachable)
                    .unwrap()
            );
            let mut bytes = [0; 2048];
            a.transmit_selected(2, &mut bytes, reserved)
                .unwrap()
                .unwrap();
            if reserved {
                assert!(!a.fast_open_attempt);
                a.reject_reserved_output();
                a.timeout(1_000_000).unwrap();
                assert!(!a.fast_open_negative);
                let mut departure = a.last_departure.unwrap();
                let payload = departure.payload;
                a.accept_reserved_output(2_000_000, &mut departure, 0, payload, true)
                    .unwrap();
            }
            assert_eq!(a.fast_open_attempt, option);
            let timeout = a.rto_deadline.unwrap();
            a.timeout(timeout - 1).unwrap();
            assert!(!a.fast_open_negative);
            a.timeout(timeout).unwrap();
            assert_eq!(core::mem::take(&mut a.fast_open_negative), option);
            let retry = packet(&mut a, timeout);
            assert!(
                wire::parse(ip(tuple()), &retry)
                    .unwrap()
                    .options
                    .fast_open
                    .is_none()
            );
            let timeout = a.rto_deadline.unwrap();
            a.timeout(timeout).unwrap();
            assert!(!a.fast_open_negative);
        }
    }
}

#[test]
fn fast_open_negative_validated_errors_reset_and_local_abort() {
    for error in [
        NetworkError::HardUnreachable,
        NetworkError::SoftUnreachable,
        NetworkError::TimeExceeded,
        NetworkError::ParameterProblem,
    ] {
        let mut a = client(100, 12);
        packet(&mut a, 0);
        assert!(!a.network_error(1, 99, error).unwrap());
        assert!(!a.network_error(2, 113, error).unwrap());
        assert!(!a.network_error(3, 100, NetworkError::SourceQuench).unwrap());
        assert!(!a.fast_open_negative);
        assert!(a.network_error(4, 100, error).unwrap());
        assert!(core::mem::take(&mut a.fast_open_negative));
        a.network_error(5, 100, error).unwrap();
        assert!(!a.fast_open_negative);
    }
    for ack in [100, 101, 113, 114] {
        let mut a = client(100, 12);
        packet(&mut a, 0);
        let segment = wire::Segment {
            header: wire::Header {
                source_port: tuple().remote.port(),
                destination_port: tuple().local.port(),
                sequence: 99,
                acknowledgment: ack,
                flags: RST | ACK,
                window: 0,
                urgent_pointer: 0,
            },
            options: Default::default(),
            raw_options: &[],
            payload: &[],
        };
        a.input(1, &segment).unwrap();
        assert!(!a.fast_open_negative);
        assert_eq!(a.state() == State::Closed, (101..=113).contains(&ack));
    }
    let mut a = client(100, 12);
    packet(&mut a, 0);
    a.timeout(400_000_000).unwrap();
    assert_eq!(a.state(), State::Closed);
    assert!(a.fast_open_negative);
    let mut a = client(100, 12);
    packet(&mut a, 0);
    a.abort();
    assert!(!a.fast_open_negative);
    let mut a = client(100, 12);
    packet(&mut a, 0);
    synack(&mut a, 12, 1);
    assert!(!a.fast_open_negative);
    a.write(b"later").unwrap();
    packet(&mut a, 2);
    a.network_error(3, 113, NetworkError::HardUnreachable)
        .unwrap();
    assert!(!a.fast_open_negative);
}

#[test]
fn fast_open_negative_ptb_keeps_existing_validation() {
    let template = client(100, 200);
    let mut cfg = template.config.clone();
    cfg.pmtud = Some(crate::PmtudConfig::new(1500));
    let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
    a.fast_open = template.fast_open;
    a.fast_open_initial = 200;
    a.write(&[42; 200]).unwrap();
    let bytes = packet(&mut a, 0);
    let size = bytes.len() as u32 + 20;
    for (seq, len, header, mtu) in [
        (99, size, 20, 68),
        (100, size + 1, 20, 68),
        (100, size, 24, 68),
        (100, size, 20, 1500),
    ] {
        assert!(!a.pmtu_feedback(1, seq, len, header, mtu).unwrap());
        assert!(!a.fast_open_negative);
    }
    assert!(a.pmtu_feedback(2, 100, size, 20, 68).unwrap());
    assert!(a.fast_open_negative);
}

#[test]
fn fast_open_negative_terminal_deadline_precedence_with_late_service() {
    for units in [1_000_000, 1_000_000_000] {
        for (application_us, service_us, expected) in [
            (100_000, 100_000, false),
            (100_000, 2_000_000, false),
            (1_000_000, 2_000_000, true),
            (1_500_000, 2_000_000, true),
        ] {
            let template = client(100, 12);
            let mut cfg = template.config.clone();
            cfg.timebase.units_per_second = units;
            let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
            a.fast_open = template.fast_open;
            a.fast_open_initial = 12;
            a.write(&[42; 12]).unwrap();
            a.set_application_timeout(Some(application_us)).unwrap();
            packet(&mut a, 0);
            assert_eq!(a.rto_deadline, Some(units));
            a.timeout(a.config.timebase.ticks_from_us(service_us))
                .unwrap();
            assert_eq!(a.state(), State::Closed);
            assert_eq!(a.fast_open_negative, expected);
        }
    }
}

#[test]
fn pending_writer_initializes_engine_not_receive_history_at_validated_handshake() {
    for units in [1_000_000, 1_000_000_000] {
        for pending in [false, true] {
            for tail in [false, true] {
                for idle in [false, true] {
                    let mut a = client(100, 12);
                    a.config.adaptive_ack = true;
                    a.config.timestamps = false;
                    a.config.timebase.units_per_second = units;
                    let ticks = |us| us * (units / 1_000_000);
                    a.ack_ato = ticks(40_000);
                    a.set_fast_open_write_pending(pending).unwrap();
                    packet(&mut a, 0);
                    synack(&mut a, 12, ticks(200));
                    assert_eq!(a.ack_engine_initialized, pending);
                    assert!(!a.fast_open_write_pending);
                    assert_eq!(a.ack_receive, Some((ticks(200), false)));
                    assert!(!a.ack_interactive);
                    if tail {
                        a.write(b"fresh").unwrap();
                        assert!(!a.ack_interactive);
                        assert_eq!(
                            a.transmit(ticks(201), &mut [0; 19]),
                            Err(Error::OutputTooSmall)
                        );
                        assert!(!a.ack_interactive);
                        a.transmit_selected(ticks(201), &mut [0; 2048], true)
                            .unwrap()
                            .unwrap();
                        let mut departure = a.last_departure.take().unwrap();
                        assert!(!a.ack_interactive);
                        a.accept_reserved_output(ticks(202), &mut departure, 0, 2, false)
                            .unwrap();
                        assert_eq!(a.ack_interactive, pending);
                        a.accept_reserved_output(ticks(203), &mut departure, 2, 3, true)
                            .unwrap();
                        assert_eq!(
                            a.ack_quick,
                            if pending {
                                a.adaptive_quick_budget()
                            } else {
                                0
                            }
                        );
                    } else {
                        packet(&mut a, ticks(201)); // Handshake ACK is not a fresh send.
                        assert!(!a.ack_interactive);
                    }
                    let next = a.receive.next();
                    let ack = if idle { a.snd_una } else { a.snd_nxt };
                    let arrival = if idle {
                        ticks(200) + a.rto() + 1
                    } else {
                        ticks(300)
                    };
                    inject(&mut a, arrival, next, ack, ACK, 8192, b"response");
                    assert_eq!(a.ack_pending, !(pending && tail && !idle));
                    assert_eq!(a.ack_receive, Some((arrival, true)));
                    assert!(a.ack_engine_initialized);
                    a.terminal(CloseReason::Reset);
                    assert!(!a.ack_engine_initialized);
                    assert!(!a.fast_open_write_pending);
                }
            }
        }
    }
    let mut invalid = client(100, 12);
    invalid.config.adaptive_ack = true;
    invalid.set_fast_open_write_pending(true).unwrap();
    packet(&mut invalid, 0);
    synack(&mut invalid, 13, 100);
    assert!(!invalid.ack_engine_initialized);
    assert!(invalid.fast_open_write_pending);
    invalid.terminal(CloseReason::Reset);
    assert!(!invalid.fast_open_write_pending);
    for reason in [
        CloseReason::Aborted,
        CloseReason::TimedOut,
        CloseReason::Reset,
    ] {
        let mut a = client(100, 12);
        a.set_fast_open_write_pending(true).unwrap();
        a.set_fast_open_write_pending(false).unwrap();
        packet(&mut a, 0);
        synack(&mut a, 12, 100);
        assert!(!a.ack_engine_initialized);
        a.terminal(reason);
        assert!(!a.fast_open_write_pending);
        assert_eq!(
            a.set_fast_open_write_pending(true),
            Err(Error::InvalidState)
        );
    }
}

#[test]
fn fast_open_reset_preserves_prior_failure_and_simultaneous_open_validation() {
    for simultaneous in [false, true] {
        for prior_failure in 0..3 {
            for valid in [false, true] {
                let mut a = client(u32::MAX - 4, 12);
                packet(&mut a, 0);
                if simultaneous {
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
                        options: Default::default(),
                        raw_options: &[],
                        payload: &[],
                    };
                    a.input(1, &syn).unwrap();
                    assert_eq!(a.state(), State::SynReceived);
                    packet(&mut a, 2);
                }
                let mut reset_time = 4;
                if prior_failure == 2 {
                    let deadline = a.rto_deadline.unwrap();
                    a.timeout(deadline).unwrap();
                    assert!(a.fast_open_negative);
                    reset_time = deadline + 1;
                } else if prior_failure == 1 {
                    // Soft ICMP retains the handshake while recording independent evidence.
                    assert!(
                        a.network_error(3, a.iss.0, NetworkError::SoftUnreachable)
                            .unwrap()
                    );
                    assert!(a.fast_open_negative);
                }
                let reset = wire::Segment {
                    header: wire::Header {
                        source_port: tuple().remote.port(),
                        destination_port: tuple().local.port(),
                        sequence: if simultaneous {
                            if valid { 1000 } else { 1001 }
                        } else {
                            99
                        },
                        acknowledgment: if valid {
                            a.iss.wrapping_add(1).0
                        } else {
                            a.iss.0
                        },
                        flags: if simultaneous { RST } else { RST | ACK },
                        window: 0,
                        urgent_pointer: 0,
                    },
                    options: Default::default(),
                    raw_options: &[],
                    payload: &[],
                };
                a.input(reset_time, &reset).unwrap();
                assert_eq!(a.state() == State::Closed, valid);
                assert_eq!(a.fast_open_negative, prior_failure != 0);
                assert!(!a.fast_open_peer_reset); // Active opens do not affect passive admission.
            }
        }
    }
}

#[test]
fn fast_open_synack_classification_shared_across_handshake_roles() {
    for simultaneous in [false, true] {
        for iss in [100, u32::MAX - 4] {
            for reserved in [false, true] {
                for prior_failure in 0..3 {
                    for acked in [0, 3, 12] {
                        let mut a = client(iss, 12);
                        let mut now = 0;
                        selected_packet(&mut a, &mut now, reserved).unwrap();
                        if simultaneous {
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
                                options: Default::default(),
                                raw_options: &[],
                                payload: &[],
                            };
                            a.input(now, &syn).unwrap();
                            assert_eq!(a.state(), State::SynReceived);
                            selected_packet(&mut a, &mut now, reserved).unwrap();
                        }
                        if prior_failure == 1 {
                            assert!(
                                a.network_error(now, iss, NetworkError::SoftUnreachable)
                                    .unwrap()
                            );
                            now += 100;
                        } else if prior_failure == 2 {
                            let deadline = a.rto_deadline.unwrap();
                            a.timeout(deadline).unwrap();
                            now = deadline + 100;
                        }
                        assert_eq!(a.fast_open_negative, prior_failure != 0);
                        synack(&mut a, acked, now);
                        assert_eq!(a.state(), State::Established);
                        assert_eq!(a.fast_open_negative, prior_failure != 0 || acked == 0);
                        assert_eq!(a.syn_data_acked, acked != 0);
                        assert_eq!(a.snd_una, Seq(iss.wrapping_add(1 + acked)));
                        assert_eq!(a.send.len(), 12 - acked as usize);
                        now += 100;
                        let bytes = selected_packet(&mut a, &mut now, reserved).unwrap();
                        let repair = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!(repair.header.sequence, iss.wrapping_add(1 + acked));
                        assert_eq!(repair.payload, &[42; 12][acked as usize..]);
                        assert_eq!(repair.header.flags & SYN, 0);
                        assert_eq!(a.snd_una, Seq(iss.wrapping_add(1 + acked)));
                    }
                }
            }
        }
    }
}

#[test]
fn inventory_tfo_partial_synack_resegmentation_counts_original_identity() {
    extern crate std;
    fn emit(a: &mut Connection, now: u64, reserved: bool) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        let n = a
            .transmit_selected(now, &mut bytes, reserved)
            .unwrap()
            .unwrap();
        if reserved {
            let mut d = a.last_departure.unwrap();
            let count = d.payload;
            a.accept_reserved_output(now, &mut d, 0, count, true)
                .unwrap();
        }
        bytes.truncate(n);
        bytes
    }
    for iss in [100, u32::MAX - 500] {
        for reserved in [false, true] {
            let mut c = config(16384, 1460);
            c.timestamps = false;
            c.sack = true;
            c.rack = true;
            let mut a = Connection::active(tuple(), c, iss, 0).unwrap();
            let mut cache = crate::fast_open::FastOpen::new().unwrap();
            cache.learn(
                0,
                tuple().local.ip(),
                tuple().remote.ip(),
                wire::FastOpenCookie::new(&[7; 8]).unwrap(),
                1460,
            );
            let cached = cache.get(0, 100, tuple().local.ip(), tuple().remote.ip());
            assert_eq!(a.prepare_fast_open(cached, &[42; 1420]).unwrap(), 1420);
            emit(&mut a, 0, reserved);
            let response = Segment {
                header: Header {
                    source_port: tuple().remote.port(),
                    destination_port: tuple().local.port(),
                    sequence: 999,
                    acknowledgment: iss.wrapping_add(101),
                    flags: SYN | ACK,
                    window: 65535,
                    urgent_pointer: 0,
                },
                options: wire::Options {
                    mss: Some(1000),
                    sack_permitted: true,
                    ..Default::default()
                },
                raw_options: &[],
                payload: &[],
            };
            a.input(10_000, &response).unwrap();
            assert_eq!(a.acknowledged, 100);
            assert_eq!(a.send.len(), 1320);
            let mut total = 0;
            for length in [1000, 320] {
                let bytes = emit(&mut a, 10_000, reserved);
                let retry = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(retry.header.sequence, iss.wrapping_add(101 + total));
                assert_eq!(retry.payload.len(), length);
                total += length as u32;
            }
            assert_eq!(a.data_flight(), 1320);
            let info = a.transport_info();
            assert_eq!(info.unacked, 2);
            assert_eq!(info.retransmitted, 2);
            assert!(info.ledger_valid);
            assert_eq!(a.transmit(10_000, &mut [0; 4096]), Ok(None));
            inject(
                &mut a,
                20_000,
                Seq(1000),
                Seq(iss.wrapping_add(1421)),
                ACK,
                65535,
                &[],
            );
            let final_info = a.transport_info();
            assert_eq!(a.acknowledged, 1420);
            assert_eq!(a.send.len(), 0);
            assert_eq!(final_info.unacked, 0);
            assert_eq!(final_info.retransmitted, 0);
            std::eprintln!(
                "TFO_INVENTORY {{\"probe\":\"partial_resegmentation\",\"iss\":{iss},\"reserved\":{reserved},\"syn_bytes\":1420,\"syn_data_acked\":100,\"new_mss\":1000,\"repair_lengths\":[1000,320],\"unacked\":{},\"retransmitted\":{},\"final_unacked\":{},\"final_delivered_segments\":{}}}",
                info.unacked,
                info.retransmitted,
                final_info.unacked,
                final_info.delivered_segments
            );
        }
    }
}

#[test]
fn authenticated_empty_syn_constructor_allows_server_first_only_after_synack() {
    for authenticated in [false, true] {
        let mut cfg = config(8192, 536);
        cfg.fast_open_early_response = true;
        let syn = wire::Segment {
            header: wire::Header {
                source_port: tuple().remote.port(),
                destination_port: tuple().local.port(),
                sequence: 100,
                acknowledgment: 0,
                flags: SYN,
                window: 8192,
                urgent_pointer: 0,
            },
            options: wire::Options {
                fast_open: Some(wire::FastOpenCookie::new(&[7; 8]).unwrap()),
                ..Default::default()
            },
            raw_options: &[],
            payload: &[],
        };
        let mut connection = Connection::passive_with_receive(
            tuple(),
            cfg,
            900,
            0,
            &syn,
            authenticated,
            &mut None,
            RxTimestamps::default(),
            RxPacketTimestamps::default(),
        )
        .unwrap();
        assert_eq!(connection.write(b"hello").unwrap(), 5);
        let first = packet(&mut connection, 0);
        let first = wire::parse(ip(tuple()), &first).unwrap();
        assert_eq!(first.header.flags & (SYN | ACK), SYN | ACK);
        assert!(first.payload.is_empty());
        assert!(!connection.transport_info().syn_data_fully_acked);
        if authenticated {
            let response = packet(&mut connection, 1);
            assert_eq!(
                wire::parse(ip(tuple()), &response).unwrap().payload,
                b"hello"
            );
        } else {
            assert_eq!(connection.transmit(1, &mut [0; 2048]).unwrap(), None);
        }
    }
}
