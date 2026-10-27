use super::*;

fn client(v6: bool, timestamps: bool, size: usize) -> Connection {
    let tuple = if v6 {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    } else {
        tuple()
    };
    let mut a = Connection::active(
        tuple,
        ConnectionConfig {
            timestamps,
            sack: true,
            ecn: true,
            nagle: false,
            ..config(8192, 1000)
        },
        u32::MAX - 100,
        0,
    )
    .unwrap();
    let mut cache = crate::fast_open::FastOpen::new().unwrap();
    cache.learn(
        0,
        tuple.local.ip(),
        tuple.remote.ip(),
        wire::FastOpenCookie::new(&[7; 8]).unwrap(),
        1000,
    );
    a.prepare_fast_open(
        cache.get(0, 100, tuple.local.ip(), tuple.remote.ip()),
        &vec![42; size],
    )
    .unwrap();
    a
}

// Returns the emitted packet; a reserved departure is accepted whole.
fn output(a: &mut Connection, selected: u64, accepted: u64, reserved: bool) -> Vec<u8> {
    let mut bytes = [0; 2048];
    let size = if reserved {
        let size = a
            .transmit_selected(selected, &mut bytes, true)
            .unwrap()
            .unwrap();
        let mut d = a.last_departure.unwrap();
        let count = d.payload;
        a.accept_reserved_output(accepted, &mut d, 0, count, true)
            .unwrap();
        size
    } else {
        a.transmit(accepted, &mut bytes).unwrap().unwrap()
    };
    bytes[..size].to_vec()
}

fn synack(a: &mut Connection, now: u64, bytes: u32, echo: Option<u32>) {
    let segment = wire::Segment {
        header: wire::Header {
            source_port: a.tuple.remote.port(),
            destination_port: a.tuple.local.port(),
            sequence: 999,
            acknowledgment: a.iss.wrapping_add(1 + bytes).0,
            flags: SYN | ACK | ECE,
            window: 8192,
            urgent_pointer: 0,
        },
        options: wire::Options {
            mss: Some(1000),
            timestamps: echo.map(|echo| (30, echo)),
            sack_permitted: true,
            window_scale: Some(3),
            ..Default::default()
        },
        raw_options: &[],
        payload: &[],
    };
    a.input(now, &segment).unwrap();
}

#[test]
fn statistics_syn_rtt_options_and_packet_delivery_matrix() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for timestamps in [false, true] {
                for (size, acked) in [(0, 0), (700, 0), (700, 1), (700, 700)] {
                    for stale in [false, true] {
                        let mut a = client(v6, timestamps, size);
                        // A failed encoding is neither a departure nor delivery.
                        assert_eq!(a.transmit(0, &mut [0; 19]), Err(Error::OutputTooSmall));
                        assert_eq!(a.syn_payload_sent, 0);
                        assert_eq!(a.transport_info().delivered_segments, 0);
                        output(&mut a, 1000, 10_000, reserved);
                        let selected = if reserved { 1000 } else { 10_000 };
                        let echo = a.timestamp_value(selected).wrapping_add(u32::from(stale));
                        synack(&mut a, 30_000, acked, timestamps.then_some(echo));
                        let info = a.transport_info();
                        if timestamps && stale {
                            // An echo outside the submitted SYN range is now
                            // rejected before negotiation or delivery accounting.
                            assert_eq!(info.state, State::SynSent);
                            assert_eq!(info.rtt_us, None);
                            assert_eq!(info.delivered_segments, 0);
                            assert!(!info.timestamps_negotiated);
                            assert!(!info.sack_negotiated && !info.window_scaling_negotiated);
                            assert!(!info.ecn_negotiated);
                            synack(&mut a, 30_001, acked, Some(echo));
                            assert_eq!(a.transport_info().delivered_segments, 0);
                            assert!(!a.handshake_complete());
                            continue;
                        }
                        assert_eq!(info.state, State::Established);
                        assert_eq!(info.rtt_us, (!timestamps || !stale).then_some(20_000));
                        assert_eq!(info.rttvar_us, 10_000); // RTTVAR = R/2: exactly one sample.
                        assert_eq!(info.timestamps_negotiated, timestamps);
                        assert!(info.sack_negotiated && info.window_scaling_negotiated);
                        assert_eq!((info.send_window_scale, info.receive_window_scale), (3, 0));
                        assert!(info.ecn_negotiated && !info.ecn_response);
                        assert_eq!(info.syn_data_acked, acked != 0);
                        assert_eq!(info.delivered_segments, 1);
                        assert!(info.delivered_segments_valid);
                        // A repeated handshake cannot change the outcome or count.
                        synack(&mut a, 30_001, acked, timestamps.then_some(echo));
                        assert_eq!(a.transport_info().delivered_segments, 1);
                        assert_eq!(a.transport_info().syn_data_acked, acked != 0);
                    }
                }
            }
        }
    }
}

#[test]
fn statistics_syn_timeout_karn_and_repaired_payload_delivery() {
    for v6 in [false, true] {
        for reserved in [false, true] {
            for timestamps in [false, true] {
                for original_echo in [false, true] {
                    let mut a = client(v6, timestamps, 700);
                    output(&mut a, 0, 0, reserved);
                    let timeout = a.next_deadline().unwrap();
                    a.timeout(timeout).unwrap();
                    output(&mut a, timeout, timeout + 2000, reserved);
                    let sent = if original_echo {
                        0
                    } else if reserved {
                        timeout
                    } else {
                        timeout + 2000
                    };
                    let echo = a.timestamp_value(sent);
                    synack(&mut a, timeout + 10_000, 0, timestamps.then_some(echo));
                    assert_eq!(a.rtt.srtt(), None);
                    assert!(!a.transport_info().syn_data_acked);
                    assert_eq!(a.transport_info().delivered_segments, 1);
                    output(&mut a, timeout + 10_000, timeout + 20_000, reserved);
                    let next = a.receive.next();
                    let end = a.snd_nxt;
                    timestamp_input(
                        &mut a,
                        timeout + 30_000,
                        next,
                        end,
                        ACK,
                        timestamps.then_some((40, echo)),
                        b"",
                    );
                    assert_eq!(a.transport_info().delivered_segments, 2);
                    assert!(a.transport_info().delivered_segments_valid);
                    assert!(!a.transport_info().syn_data_acked);
                    assert_eq!(a.rtt.srtt(), None); // Retransmitted data is Karn-ineligible too.
                }
            }
        }
    }
}

#[test]
fn statistics_syn_partial_ack_without_repair_does_not_count_payload_twice() {
    for reserved in [false, true] {
        let mut a = client(false, false, 700);
        output(&mut a, 0, 0, reserved);
        synack(&mut a, 1000, 1, None);
        let next = a.receive.next();
        let end = a.snd_nxt;
        timestamp_input(&mut a, 2000, next, end, ACK, None, b"");
        assert_eq!(a.transport_info().delivered_segments, 1);
        assert!(a.transport_info().delivered_segments_valid);
        assert!(a.transport_info().syn_data_acked);
    }
}

#[test]
fn statistics_invalid_ack_empty_miss_and_missing_timestamp_fallback() {
    for size in [0, 700] {
        let mut a = client(false, true, size);
        output(&mut a, 0, 0, true);
        synack(&mut a, 1000, size as u32 + 1, Some(0));
        assert_eq!(a.state(), State::SynSent);
        assert!(!a.transport_info().syn_data_acked);
        assert_eq!(a.transport_info().delivered_segments, 0);
        // A SYN-ACK without TS declines negotiation; preserve local-clock RTT.
        synack(&mut a, 2000, size as u32, None);
        assert_eq!(a.rtt.srtt(), Some(2000));
        assert!(!a.transport_info().timestamps_negotiated);
    }
    let mut a = Connection::active(tuple(), config(8192, 1000), 0, 0).unwrap();
    assert_eq!(a.prepare_fast_open(None, b"not in SYN").unwrap(), 0);
    a.write(b"queued, not transmitted").unwrap();
    output(&mut a, 0, 0, true);
    synack(&mut a, 1000, 0, None);
    assert!(!a.transport_info().syn_data_acked);
    assert_eq!(a.syn_payload_sent, 0);
    assert_eq!(a.transport_info().delivered_segments, 1);
}

#[test]
fn statistics_data_cumulative_sack_duplicate_and_dsack_shared_paths() {
    for sack in [false, true] {
        for reserved in [false, true] {
            for iss in [0, u32::MAX - 500] {
                let (mut a, _) = pair(
                    ConnectionConfig {
                        sack,
                        nagle: false,
                        ..config(8192, 1000)
                    },
                    iss,
                );
                a.write(&[0; 2000]).unwrap();
                output(&mut a, 100, 100, reserved);
                output(&mut a, 100, 100, reserved);
                assert_eq!(a.transport_info().delivered_segments, 1);
                if sack {
                    rack_sack(&mut a, 200, 0, &[(1000, 2000)]);
                    assert_eq!(a.transport_info().delivered_segments, 2);
                    rack_sack(&mut a, 201, 0, &[(1000, 2000)]);
                    assert_eq!(a.transport_info().delivered_segments, 2);
                }
                rack_sack(&mut a, 300, 500, &[]);
                assert_eq!(
                    a.transport_info().delivered_segments,
                    if sack { 2 } else { 1 }
                );
                rack_sack(&mut a, 400, 2000, &[]);
                assert_eq!(a.transport_info().delivered_segments, 3);
                rack_sack(&mut a, 401, 2000, &[(0, 1000)]);
                assert_eq!(a.transport_info().delivered_segments, 3);
                assert!(a.transport_info().delivered_segments_valid);
            }
        }
    }
}

#[test]
fn statistics_retransmitted_syn_cannot_sample_even_when_original_data_is_acked() {
    for reserved in [false, true] {
        for acked in [1, 700] {
            let mut a = client(false, true, 700);
            output(&mut a, 0, 0, reserved);
            let timeout = a.next_deadline().unwrap();
            a.timeout(timeout).unwrap();
            output(&mut a, timeout, timeout + 2000, reserved);
            let echo = a.timestamp_value(0); // Delayed original SYN+data response.
            synack(&mut a, timeout + 10_000, acked, Some(echo));
            assert_eq!(a.rtt.srtt(), None);
            assert!(a.transport_info().syn_data_acked);
            assert_eq!(a.transport_info().delivered_segments, 1);
            assert!(a.transport_info().delivered_segments_valid);
        }
    }
}

#[test]
fn statistics_options_are_negotiated_not_configured_and_passive_requires_timestamp() {
    let mut a = Connection::active(
        tuple(),
        ConnectionConfig {
            timestamps: true,
            sack: true,
            ecn: true,
            ..config(65_536, 1000)
        },
        0,
        0,
    )
    .unwrap();
    output(&mut a, 0, 0, false);
    assert!(a.local_scale > 0);
    timestamp_input(&mut a, 1000, Seq(100), Seq(1), SYN | ACK, None, b"");
    let info = a.transport_info();
    assert!(!info.timestamps_negotiated && !info.sack_negotiated);
    assert!(!info.window_scaling_negotiated && !info.ecn_negotiated);
    assert_eq!((info.send_window_scale, info.receive_window_scale), (0, 0));

    let mut a = client(false, true, 0);
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(a.tuple), &bytes).unwrap();
    let mut b = Connection::passive(reverse(a.tuple), a.config.clone(), 0, 0, &syn).unwrap();
    output(&mut b, 0, 10_000, true);
    let next = b.receive.next();
    timestamp_input(&mut b, 20_000, next, Seq(1), ACK, None, b"");
    assert_eq!(b.state(), State::SynReceived);
    assert_eq!(b.rtt.srtt(), None);
    assert_eq!(b.transport_info().delivered_segments, 0);
    let echo = b.timestamp_value(0);
    timestamp_input(&mut b, 30_000, next, Seq(1), ACK, Some((30, echo)), b"");
    assert_eq!(b.rtt.srtt(), Some(20_000));
    assert_eq!(b.rtt.variance(), 10_000); // RTTVAR = R/2: exactly one sample.
    assert_eq!(b.transport_info().delivered_segments, 1);
}

#[test]
fn statistics_standalone_fin_and_data_fin_are_not_double_counted() {
    for reserved in [false, true] {
        for data in [false, true] {
            let (mut a, _) = pair(config(8192, 1000), 0);
            if data {
                a.write(b"FIN payload").unwrap();
            }
            a.shutdown().unwrap();
            output(&mut a, 100, 200, reserved);
            let next = a.receive.next();
            let end = a.snd_nxt;
            timestamp_input(&mut a, 300, next, end, ACK, None, b"");
            assert_eq!(a.transport_info().delivered_segments, 2);
            assert!(a.transport_info().delivered_segments_valid);
            timestamp_input(&mut a, 400, next, end, ACK, None, b"");
            assert_eq!(a.transport_info().delivered_segments, 2);
        }
    }
}

#[test]
fn statistics_fin_current_replacement_not_historical_standalone() {
    for (reserved, prefix) in [(false, 0), (true, 0), (true, 40), (true, 100)] {
        let (mut a, _) = pair(
            ConnectionConfig {
                sack: false,
                tlp: false,
                nagle: false,
                ..config(8192, 1000)
            },
            0,
        );
        a.write(&[0; 100]).unwrap();
        output(&mut a, 100, 100, reserved);
        a.shutdown().unwrap();
        let fin = output(&mut a, 100, 100, reserved); // Same departure permits data+FIN RTO.
        let fin = wire::parse(ip(a.tuple), &fin).unwrap();
        assert!(fin.payload.is_empty() && fin.header.flags & FIN != 0);
        assert!(a.fin_needs_separate_credit);
        assert_eq!(a.transport_info().delivered_segments, 1);
        let timeout = a.next_deadline().unwrap();
        a.timeout(timeout).unwrap();
        assert_eq!(
            a.transmit_selected(timeout, &mut [0; 19], reserved),
            Err(Error::OutputTooSmall)
        );
        assert!(a.fin_needs_separate_credit);
        let mut bytes = [0; 2048];
        let n = a
            .transmit_selected(timeout, &mut bytes, reserved)
            .unwrap()
            .unwrap();
        let packet = wire::parse(ip(a.tuple), &bytes[..n]).unwrap();
        assert_eq!(packet.payload.len(), 100);
        assert_ne!(packet.header.flags & FIN, 0);
        if reserved {
            assert!(a.fin_needs_separate_credit); // Selection is not acceptance.
            a.reject_reserved_output();
            assert!(a.fin_needs_separate_credit);
            let mut d = a.last_departure.unwrap();
            if prefix != 0 {
                a.accept_reserved_output(timeout + 50, &mut d, 0, prefix, false)
                    .unwrap();
                assert!(a.fin_needs_separate_credit); // Prefix carries no FIN.
            }
            assert_eq!(
                a.accept_reserved_output(timeout + 100, &mut d, prefix, 101, true),
                Err(Error::InvalidArgument)
            );
            assert!(a.fin_needs_separate_credit);
            a.accept_reserved_output(timeout + 100, &mut d, prefix, 100 - prefix, true)
                .unwrap();
        }
        // The accepted FIN fragment carries payload unless the prefix took it all;
        // only a payload-free FIN needs its own credit here.
        assert_eq!(a.fin_needs_separate_credit, prefix == 100);
        let next = a.receive.next();
        let end = a.snd_nxt;
        timestamp_input(&mut a, timeout + 200, next, end, ACK, None, b"");
        assert_eq!(
            a.transport_info().delivered_segments,
            2 + u64::from(prefix != 0),
            "reserved={reserved}"
        );
        assert!(a.transport_info().delivered_segments_valid);
    }
}

#[test]
fn statistics_fin_payload_credit_distinguishes_combined_from_separate_fin() {
    for reserved in [false, true] {
        for initially_combined in [false, true] {
            let (mut a, _) = pair(
                ConnectionConfig {
                    sack: true,
                    tlp: false,
                    nagle: false,
                    ..config(8192, 1000)
                },
                0,
            );
            a.write(&[0; 100]).unwrap();
            if !initially_combined {
                output(&mut a, 100, 100, reserved);
            }
            a.shutdown().unwrap();
            output(&mut a, 100, 100, reserved);
            rack_sack(&mut a, 200, 0, &[(0, 100)]);
            assert_eq!(a.transport_info().delivered_segments, 2);
            assert!(a.transport_info().delivered_segments_valid);
            let timeout = a.next_deadline().unwrap();
            a.timeout(timeout).unwrap();
            let mut bytes = [0; 2048];
            let n = a
                .transmit_selected(timeout, &mut bytes, reserved)
                .unwrap()
                .unwrap();
            let packet = wire::parse(ip(a.tuple), &bytes[..n]).unwrap();
            assert_eq!(packet.payload.len(), 100);
            assert_ne!(packet.header.flags & FIN, 0);
            if reserved {
                assert!(a.transport_info().delivered_segments_valid);
                a.reject_reserved_output();
                assert!(a.transport_info().delivered_segments_valid);
                let mut d = a.last_departure.unwrap();
                a.accept_reserved_output(timeout + 100, &mut d, 0, 100, true)
                    .unwrap();
            }
            assert!(a.transport_info().delivered_segments_valid);
            let next = a.receive.next();
            let end = a.snd_nxt;
            timestamp_input(&mut a, timeout + 200, next, end, ACK, None, b"");
            // Previously credited data supplies no new data credit; a FIN
            // first attached to that credited data still needs control credit.
            assert_eq!(a.transport_info().delivered_segments, if initially_combined { 2 } else { 3 });
            assert!(a.transport_info().delivered_segments_valid);
            assert!(a.transport_info().ledger_valid);
        }
    }
}

#[test]
fn statistics_combined_fin_can_be_replaced_by_accepted_standalone_fin() {
    for reserved in [false, true] {
        let (mut a, _) = pair(
            ConnectionConfig {
                sack: false,
                tlp: false,
                nagle: false,
                ..config(8192, 1000)
            },
            0,
        );
        a.write(&[0; 100]).unwrap();
        a.shutdown().unwrap();
        let fin = output(&mut a, 100, 100, reserved);
        let fin = wire::parse(ip(a.tuple), &fin).unwrap();
        assert!(fin.payload.len() == 100 && fin.header.flags & FIN != 0);
        assert!(!a.fin_needs_separate_credit);
        let next = a.receive.next();
        let fin = a.fin_sequence.unwrap();
        timestamp_input(&mut a, 200, next, fin, ACK, None, b""); // Payload only.
        assert_eq!(a.transport_info().delivered_segments, 2);
        let timeout = a.next_deadline().unwrap();
        a.timeout(timeout).unwrap();
        let mut bytes = [0; 2048];
        let n = a
            .transmit_selected(timeout, &mut bytes, reserved)
            .unwrap()
            .unwrap();
        let packet = wire::parse(ip(a.tuple), &bytes[..n]).unwrap();
        assert!(packet.payload.is_empty());
        assert_ne!(packet.header.flags & FIN, 0);
        if reserved {
            assert!(!a.fin_needs_separate_credit);
            a.reject_reserved_output();
            assert!(!a.fin_needs_separate_credit);
            let mut d = a.last_departure.unwrap();
            a.accept_reserved_output(timeout + 100, &mut d, 0, 0, true)
                .unwrap();
        }
        assert!(a.fin_needs_separate_credit);
        timestamp_input(
            &mut a,
            timeout + 200,
            next,
            fin.wrapping_add(1),
            ACK,
            None,
            b"",
        );
        assert_eq!(a.transport_info().delivered_segments, 3);
        assert!(a.transport_info().delivered_segments_valid);
    }
}
