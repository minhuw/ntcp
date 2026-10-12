use super::*;

fn output(c: &mut Connection, now: u64, reserved: bool) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let n = c
        .transmit_selected(now, &mut bytes, reserved)
        .unwrap()
        .unwrap();
    if reserved {
        let mut departure = c.last_departure.unwrap();
        c.accept_reserved_output(now, &mut departure, 0, 0, true)
            .unwrap();
    }
    bytes.truncate(n);
    bytes
}

fn stamps(value: u64) -> RxPacketTimestamps {
    RxPacketTimestamps {
        software: Some(crate::RxTimestamp {
            value,
            clock: crate::TimestampClock::RealtimeNanoseconds,
        }),
        hardware: None,
    }
}

fn syn(sequence: u32, fin: bool) -> Segment<'static> {
    Segment {
        header: Header {
            source_port: 2000,
            destination_port: 1000,
            sequence,
            acknowledgment: 0,
            flags: SYN | PSH | URG | if fin { FIN } else { 0 },
            window: 64,
            urgent_pointer: 11,
        },
        options: wire::Options {
            sack_permitted: true,
            ..Default::default()
        },
        raw_options: &[],
        payload: b"abcdefghij",
    }
}

#[test]
fn ordinary_syn_deferral_window_controls_overlap_time_and_output_matrix() {
    for reserved in [false, true] {
        for passive in [false, true] {
            for sequence in [0, u32::MAX - 4] {
                for capacity in [1, 4, 10, 16] {
                    for fin in [false, true] {
                        for retransmit in [false, true] {
                            let initial = syn(sequence, fin);
                            let mut cfg = config(capacity, 8);
                            cfg.sack = true;
                            let mut metadata = RxTimestamps::default();
                            metadata.resize(4, usize::MAX).unwrap();
                            let mut c = if passive {
                                Connection::passive_with_receive(
                                    tuple(),
                                    cfg,
                                    100,
                                    10,
                                    &initial,
                                    false,
                                    &mut None,
                                    metadata,
                                    stamps(111),
                                )
                                .unwrap()
                            } else {
                                let mut c = Connection::active(tuple(), cfg, 100, 0).unwrap();
                                c.rx_timestamps = metadata;
                                output(&mut c, 0, reserved);
                                c.input_with_timestamps(10, 0, &initial, stamps(111))
                                    .unwrap();
                                c
                            };
                            let start = Seq(sequence.wrapping_add(1));
                            let count = capacity.min(10);
                            let eof = fin && capacity > 10;
                            assert_eq!(c.receive.next(), start);
                            assert_eq!(c.receive_used, count);
                            assert_eq!(c.received_total, 0);
                            assert_eq!(c.rx_timestamps.at(0), stamps(111));
                            assert_eq!(
                                c.rx_timestamps.resize(0, usize::MAX),
                                Err(Error::WouldBlock)
                            );
                            assert_eq!(c.peek_rx_timestamps(1), Err(Error::InvalidArgument));
                            assert_eq!(c.receive.readable(), 0);
                            assert!(!c.receive.eof());
                            assert!(!c.receive.take_push());
                            assert_eq!(c.rcv_up, None);
                            assert_eq!(c.receive.sack_blocks(4), [None; 4]);
                            assert!(!c.events_pending());
                            assert_eq!(c.read(&mut [0; 16]), Err(Error::WouldBlock));
                            // A retry cannot replace the retained first arrival or its controls/time.
                            let retry = Segment {
                                payload: b"XXXXXXXXXX",
                                ..initial
                            };
                            c.input_with_timestamps(11, 0, &retry, stamps(222)).unwrap();
                            assert_eq!(c.state(), State::SynReceived);
                            assert_eq!(c.receive.next(), start);
                            assert_eq!(c.transmit(12, &mut []), Err(Error::OutputTooSmall));
                            let bytes = output(&mut c, 12, reserved);
                            let reply = wire::parse(ip(tuple()), &bytes).unwrap();
                            assert_eq!(reply.header.acknowledgment, start.0);
                            assert_eq!(reply.header.window as usize, capacity);
                            assert_eq!(c.advertised_edge, start.wrapping_add(capacity as u32));
                            assert_eq!(c.receive_window() as usize, capacity);
                            let crossing_synack = !passive && retransmit;
                            let final_ack = Segment {
                                header: Header {
                                    sequence: if crossing_synack { sequence } else { start.0 },
                                    acknowledgment: 101,
                                    flags: ACK | if crossing_synack { SYN } else { 0 },
                                    urgent_pointer: 0,
                                    ..initial.header
                                },
                                payload: if retransmit { b"XXXXXXXXXXkl" } else { b"" },
                                ..initial
                            };
                            crate::allocation_tests::fail_after(0, || {
                                c.input_with_timestamps(20, 0, &final_ack, stamps(333))
                            })
                            .unwrap();
                            assert!(c.handshake_complete());
                            assert!(c.deferred_syn.is_none());
                            let expected = if retransmit && capacity > 10 && !fin {
                                12
                            } else {
                                count
                            };
                            assert_eq!(c.receive_used, expected);
                            assert_eq!(c.received_total, expected as u64);
                            assert_eq!(
                                c.receive.next(),
                                start.wrapping_add(expected as u32 + u32::from(eof))
                            );
                            assert_eq!(c.receive.eof(), eof);
                            assert_eq!(c.rx_timestamps.at(0), stamps(111));
                            assert_eq!(
                                c.last_data_received,
                                if expected > count { 20 } else { 10 }
                            );
                            if expected > count {
                                assert_eq!(c.rx_timestamps.at(10), stamps(333));
                            }
                            let events = c.take_events();
                            assert!(events.connected && events.readable);
                            assert_eq!(events.pushed, capacity >= 10);
                            assert_eq!(events.urgent, Some(10));
                            assert_eq!(events.half_closed, eof);
                            // An identical completing packet cannot double-account or replace bytes.
                            c.input_with_timestamps(21, 0, &final_ack, stamps(444))
                                .unwrap();
                            assert_eq!(c.receive_used, expected);
                            assert_eq!(c.received_total, expected as u64);
                            let mut out = [0; 16];
                            assert_eq!(c.read(&mut out), Ok(expected));
                            assert_eq!(&out[..count], &initial.payload[..count]);
                            if expected > count {
                                assert_eq!(&out[count..expected], b"kl");
                            }
                            assert_eq!(
                                c.read(&mut out),
                                if eof { Ok(0) } else { Err(Error::WouldBlock) }
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn ordinary_syn_invalid_completion_reset_abort_and_timeout_never_publish() {
    for finish in [0, 1, 2, 3] {
        let initial = syn(0, true);
        let mut metadata = RxTimestamps::default();
        metadata.resize(2, usize::MAX).unwrap();
        let mut c = Connection::passive_with_receive(
            tuple(),
            config(16, 8),
            100,
            0,
            &initial,
            false,
            &mut None,
            metadata,
            stamps(111),
        )
        .unwrap();
        packet(&mut c, 1);
        for ack in [100, 102] {
            inject(&mut c, 2, Seq(1), Seq(ack), ACK, 64, b"XXXXXXXXXX");
            assert!(!c.handshake_complete());
            assert_eq!(c.receive.next(), Seq(1));
            assert_eq!(c.receive.readable(), 0);
            assert_eq!(c.receive_used, 10);
            assert!(!c.receive.eof());
            assert_eq!(c.rcv_up, None);
            assert!(!c.events_pending());
        }
        match finish {
            0 => inject(&mut c, 3, Seq(1), Seq(0), RST, 64, b""),
            1 => c.abort(),
            2 => c.timeout(c.user_deadline().unwrap()).unwrap(),
            _ => {
                // The staged endpoint is NOT the protocol frontier for RST validation.
                inject(&mut c, 3, Seq(11), Seq(0), RST, 64, b"");
                assert_eq!(c.state(), State::SynReceived);
                assert_eq!(c.receive.next(), Seq(1));
                inject(&mut c, 4, Seq(1), Seq(101), ACK, 64, b"");
                let mut out = [0; 10];
                assert_eq!(c.read(&mut out), Ok(10));
                assert_eq!(&out, initial.payload);
                continue;
            }
        }
        assert_eq!(c.state(), State::Closed);
        assert!(c.deferred_syn.is_none());
        assert_eq!(c.receive_used, 0);
        assert_eq!(c.rx_timestamps.status().retained_ranges, 0);
        assert!(!c.receive.has_data());
        assert!(!c.receive.eof());
        assert_eq!(c.terminal_readable_bytes(), 0);
        assert_eq!(c.read_terminal(&mut [0; 16]), Ok(0));
        let events = c.take_events();
        assert!(!events.readable && !events.pushed && !events.half_closed);
        assert_eq!(events.urgent, None);
    }
}

#[test]
fn ordinary_syn_zero_window_does_not_stage_text_or_fin() {
    let mut c = Connection::active(tuple(), config(16, 8), 100, 0).unwrap();
    c.syn_window = 0;
    packet(&mut c, 0);
    c.input(1, &syn(u32::MAX, true)).unwrap();
    assert_eq!(c.receive.next(), Seq(0));
    assert_eq!(c.receive_used, 0);
    let bytes = packet(&mut c, 2);
    let reply = wire::parse(ip(tuple()), &bytes).unwrap();
    assert_eq!((reply.header.acknowledgment, reply.header.window), (0, 0));
    inject(&mut c, 3, Seq(0), Seq(101), ACK, 64, b"ignored");
    assert!(c.handshake_complete());
    assert_eq!(c.receive.readable(), 0);
    assert!(!c.receive.eof());
    assert_eq!(c.read(&mut [0; 16]), Err(Error::WouldBlock));
}
