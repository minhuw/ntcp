use super::*;

fn stamps(value: u64) -> RxPacketTimestamps {
    RxPacketTimestamps {
        software: Some(RxTimestamp {
            value,
            clock: TimestampClock::RealtimeNanoseconds,
        }),
        hardware: Some(RxTimestamp {
            value: value + 10,
            clock: TimestampClock::DeviceTicks {
                identity: 7,
                units_per_second: None,
            },
        }),
    }
}

#[test]
fn reopened_syn_data_keeps_ordinary_tfo_authorization_window_and_first_receive_metadata() {
    for mode in 0..4 {
        // disabled, cookie-required, application-protected, pending quota full
        for token in 0..4 {
            // absent, request, invalid, valid
            for capacity in [3, 8] {
                let mut cfg = config();
                cfg.connection.timestamps = true;
                cfg.connection.receive_capacity = capacity;
                let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
                b.set_listener_rx_timestamp_capacity(listener, 3).unwrap();
                b.enable_fast_open().unwrap();
                if mode != 0 {
                    b.set_listener_fast_open(listener, 1).unwrap();
                }
                if mode == 2 {
                    b.set_listener_fast_open_early_data_policy(
                        listener,
                        FastOpenEarlyDataPolicy::ApplicationProtected,
                    )
                    .unwrap();
                }
                let tuple = Tuple {
                    local: addresses().1,
                    remote: addresses().0,
                };
                let cookie = crate::fast_open::issue(&[2; 32], ip.destination, ip.source, 0);
                let mut options = vec![1, 1, 8, 10];
                options.extend_from_slice(&ts.wrapping_add(1).to_be_bytes());
                options.extend_from_slice(&0u32.to_be_bytes());
                if token == 1 {
                    options.extend_from_slice(&[34, 2, 1, 1]);
                }
                if token >= 2 {
                    options.extend_from_slice(&[34, 10]);
                    options.extend_from_slice(if token == 3 {
                        cookie.as_bytes()
                    } else {
                        &[0xa5; 8]
                    });
                    options.extend_from_slice(&[1, 1]);
                }
                let sequence = h.acknowledgment; // exactly peer FIN+1
                let header = wire::Header {
                    source_port: h.destination_port,
                    destination_port: h.source_port,
                    sequence,
                    acknowledgment: 0,
                    flags: wire::SYN | wire::PSH | wire::URG,
                    window: 1024,
                    urgent_pointer: 3,
                };
                let mut syn = vec![0; 128];
                let n = wire::encode(ip, header, &options, b"data", &mut syn).unwrap();
                syn.truncate(n);
                if mode == 3 {
                    // Fill the real listener's pending TFO quota with another child.
                    let mut quota_options = options[..12].to_vec();
                    quota_options.extend_from_slice(&[34, 10]);
                    quota_options.extend_from_slice(cookie.as_bytes());
                    quota_options.extend_from_slice(&[1, 1]);
                    let mut quota = [0; 128];
                    let n = wire::encode(
                        ip,
                        wire::Header {
                            source_port: header.source_port + 1,
                            ..header
                        },
                        &quota_options,
                        b"data",
                        &mut quota,
                    )
                    .unwrap();
                    b.input(3_500, ip, &quota[..n]).unwrap();
                    let other = b.accept(listener).unwrap();
                    assert_eq!(b.state(other), Ok(State::SynReceived));
                    assert_eq!(b.readable_bytes(other), Ok(capacity.min(4)));
                    packets(&mut b, 3_500);
                }
                let old_options = b.received_ipv4_options(old).unwrap();
                let old_stamps = b.rx_timestamp_status(old).unwrap();
                let baseline = b.buffer_bytes();
                let deadline = b.next_deadline();
                // Invalid physical timestamp clocks and segmented SYN metadata
                // fail before tuple ownership or saved observations can change.
                assert_eq!(
                    b.input_with_metadata(
                        4_000,
                        ip,
                        0,
                        Ipv4Options::default(),
                        &syn,
                        RxPacketMetadata {
                            timestamps: stamps(99),
                            tcp_segment_size: core::num::NonZeroU16::new(2),
                            ..Default::default()
                        }
                    ),
                    Err(EndpointError::Connection(Error::InvalidArgument))
                );
                let bad_stamps = RxPacketTimestamps {
                    hardware: Some(RxTimestamp {
                        value: 1,
                        clock: TimestampClock::CallerTicks(CallerTimebase::default()),
                    }),
                    ..stamps(99)
                };
                assert_eq!(
                    b.input_with_timestamps(4_000, ip, 0, Ipv4Options::default(), &syn, bad_stamps),
                    Err(EndpointError::Connection(Error::InvalidArgument))
                );
                let mut stale = syn.clone();
                stale[24..28].copy_from_slice(&ts.wrapping_sub(1).to_be_bytes());
                stale[16..18].fill(0);
                let sum = wire::checksum(ip, &stale).unwrap();
                stale[16..18].copy_from_slice(&sum.to_be_bytes());
                assert_eq!(
                    b.input_with_timestamps(
                        4_000,
                        ip,
                        0,
                        Ipv4Options::default(),
                        &stale,
                        stamps(99)
                    ),
                    Ok(InputDisposition::Processed)
                );
                assert_eq!(b.connection_id(tuple), Some(old));
                assert_eq!(b.buffer_bytes(), baseline);
                assert_eq!(b.received_ipv4_options(old).unwrap(), old_options);
                assert_eq!(b.rx_timestamp_status(old).unwrap(), old_stamps);
                // The TIME-WAIT answers the stale SYN with its ACK.
                assert_time_wait_ack(&packets(&mut b, 4_000), h);
                assert_eq!(b.next_deadline(), deadline);
                b.input_with_timestamps(5_000, ip, 0, Ipv4Options::default(), &syn, stamps(111))
                    .unwrap();
                let child = b.connection_id(tuple).unwrap();
                assert_ne!(child, old);
                assert_eq!(b.state(old), Ok(State::Closed));
                assert_eq!(b.state(child), Ok(State::SynReceived));
                let early = mode == 2 || mode == 1 && token == 3;
                // Recognized TFO without authorization discards SYN data. A
                // disabled service still stages ordinary SYN text with no TFO.
                let count = if early || mode == 0 && token == 0 {
                    capacity.min(4)
                } else {
                    0
                };
                assert_eq!(b.readable_bytes(child), Ok(if early { count } else { 0 }));
                if early {
                    assert_eq!(b.accept(listener), Ok(child));
                } else {
                    assert_eq!(
                        b.accept(listener),
                        Err(EndpointError::Connection(Error::WouldBlock))
                    );
                }
                let output = packets(&mut b, 5_000);
                assert_eq!(output.len(), 1);
                let synack = wire::parse(output[0].0, &output[0].1).unwrap();
                assert_eq!(
                    synack.header.acknowledgment,
                    sequence.wrapping_add(1 + if early { count as u32 } else { 0 })
                );
                assert_eq!(synack.options.timestamps.unwrap().1, ts.wrapping_add(1));
                assert_eq!(
                    synack.options.fast_open.is_some(),
                    mode != 0 && mode != 2 && token != 0
                );
                assert!(crate::seq::Seq(synack.header.sequence).after(crate::seq::Seq(h.sequence)));
                let iss = synack.header.sequence;
                let local_ts = synack.options.timestamps.unwrap().0;
                // A duplicate cannot overwrite accepted first-arrival timestamps.
                b.input_with_timestamps(6_000, ip, 0, Ipv4Options::default(), &syn, stamps(999))
                    .unwrap();
                let ack = tw_segment(
                    ip,
                    h,
                    synack.header.acknowledgment,
                    iss.wrapping_add(1),
                    wire::ACK,
                    Some((ts.wrapping_add(2), local_ts)),
                );
                b.input_with_timestamps(7_000, ip, 0, Ipv4Options::default(), &ack, stamps(222))
                    .unwrap();
                assert_eq!(b.state(child), Ok(State::Established));
                if !early {
                    assert_eq!(b.accept(listener), Ok(child));
                }
                let mut read = [0; 8];
                if count != 0 {
                    let observation = b.peek_rx_timestamps(child, count).unwrap().unwrap();
                    assert_eq!((observation.start, observation.end), (0, count as u64));
                    assert_eq!(observation.timestamps, stamps(111));
                    assert_eq!(b.read(child, &mut read), Ok(count));
                    assert_eq!(&read[..count], &b"data"[..count]);
                } else {
                    assert_eq!(b.peek_rx_timestamps(child, 0), Ok(None));
                    assert_eq!(
                        b.read(child, &mut read),
                        Err(EndpointError::Connection(Error::WouldBlock))
                    );
                }
                assert_eq!(b.readable_bytes(child), Ok(0));
                assert_eq!(b.rx_timestamp_status(child).unwrap().retained_ranges, 0);
                assert_eq!(b.rx_timestamp_status(old).unwrap(), old_stamps);
            }
        }
    }
}

#[test]
fn reopened_data_syn_completes_with_real_peer_without_replay_or_double_delivery() {
    for enabled in [false, true] {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        cfg.reuse_time_wait = true;
        let (local, remote) = addresses();
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
        a.enable_fast_open().unwrap();
        b.enable_fast_open().unwrap();
        let listener = b.listen(remote, 4).unwrap();
        b.set_listener_fast_open(listener, 1).unwrap();
        let (first, count) = a.connect_fast_open(0, local, remote, b"cold").unwrap();
        assert_eq!(count, 0);
        pump(&mut a, &mut b, 1_000);
        let old = b.accept(listener).unwrap();
        a.write(first, b"old client").unwrap();
        let stale_remote = packets(&mut a, 2_000);
        deliver(&mut b, 2_000, stale_remote.clone());
        b.write(old, b"old server").unwrap();
        let stale_local = packets(&mut b, 2_000);
        deliver(&mut a, 2_000, stale_local.clone());
        b.shutdown(old).unwrap();
        pump(&mut a, &mut b, 3_000);
        a.shutdown(first).unwrap();
        pump(&mut a, &mut b, 4_000);
        assert_eq!(b.state(old), Ok(State::TimeWait));
        a.release(first).unwrap();
        b.set_listener_fast_open(listener, usize::from(enabled))
            .unwrap();
        let (second, count) = a
            .connect_fast_open(10_000, local, remote, b"new stream")
            .unwrap();
        assert_eq!(count, 10);
        let syn = packets(&mut a, 11_000);
        assert_eq!(syn.len(), 1);
        assert_eq!(
            wire::parse(syn[0].0, &syn[0].1).unwrap().payload,
            b"new stream"
        );
        deliver(&mut b, 11_000, syn);
        let child = b
            .connection_id(Tuple {
                local: remote,
                remote: local,
            })
            .unwrap();
        assert_ne!(child, old);
        assert_eq!(b.state(child), Ok(State::SynReceived));
        assert_eq!(b.readable_bytes(child), Ok(if enabled { 10 } else { 0 }));
        pump(&mut a, &mut b, 12_000);
        assert_eq!(b.accept(listener), Ok(child));
        assert_eq!(a.state(second), Ok(State::Established));
        assert_eq!(b.state(child), Ok(State::Established));
        deliver(&mut b, 13_000, stale_remote);
        deliver(&mut a, 13_000, stale_local);
        let mut read = [0; 32];
        assert_eq!(b.read(child, &mut read), Ok(10));
        assert_eq!(&read[..10], b"new stream");
        assert_eq!(b.readable_bytes(child), Ok(0));
        assert_eq!(a.readable_bytes(second), Ok(0));
        b.write(child, b"new reply").unwrap();
        pump(&mut a, &mut b, 14_000);
        assert_eq!(a.read(second, &mut read), Ok(9));
        assert_eq!(&read[..9], b"new reply");
        assert_eq!(b.state(old), Ok(State::Closed));
    }
}

#[test]
fn data_syn_output_reservation_preserves_old_owner_until_retry() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    let (mut b, _, old, ip, h, ts) = time_wait_endpoint(cfg);
    b.enable_output_reservations().unwrap();
    let duplicate_fin = tw_segment(
        ip,
        h,
        h.acknowledgment.wrapping_sub(1),
        h.sequence,
        wire::ACK | wire::FIN,
        Some((ts, 0)),
    );
    b.input(4_000, ip, &duplicate_fin).unwrap();
    let (_, attempt) = b
        .poll_reserved_transmit_for(4_000, old, &mut [0; 128], 64)
        .unwrap();
    let attempt = attempt.unwrap();
    let before = (
        b.buffer_bytes(),
        b.next_deadline(),
        b.received_ipv4_options(old).unwrap(),
    );
    let syn = tw_segment_with_payload(
        ip,
        h,
        h.acknowledgment,
        0,
        wire::SYN,
        Some((ts + 1, 0)),
        b"data",
    );
    assert_eq!(b.input(5_000, ip, &syn), Err(EndpointError::OutputReserved));
    assert_eq!(
        b.connection_id(Tuple {
            local: addresses().1,
            remote: addresses().0
        }),
        Some(old)
    );
    assert_eq!(
        (
            b.buffer_bytes(),
            b.next_deadline(),
            b.received_ipv4_options(old).unwrap()
        ),
        before
    );
    b.accept_transmit(5_000, attempt).unwrap();
    b.input(6_000, ip, &syn).unwrap();
    assert_ne!(
        b.connection_id(Tuple {
            local: addresses().1,
            remote: addresses().0
        }),
        Some(old)
    );
    assert_eq!(b.state(old), Ok(State::Closed));
}

//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//= reason=Only a SYN without ACK or RST to a TIME-WAIT connection reaches reopen_time_wait, whose reuse_syn freshness uses both the incoming sequence number and its Timestamps option when present. Reuse enabled versus disabled leaves results, state, resources, deadlines and emitted bytes identical in CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK and CLOSING across flag, checksum, timestamp and sequence variants.
//# The following paragraphs summarize the processing of SYN segments
//# received for connections in the TIME-WAIT state. The processing of SYN
//# segments received for connections in all other states is unchanged. Both
//# the ISN (Initial Sequence Number) and the Timestamps option (if present)
//# of the incoming SYN segment are included in the heuristics performed for
//# allowing a high connection-establishment rate.
#[test]
fn reuse_toggle_preserves_non_time_wait_states_and_non_request_flags() {
    fn observe(
        reuse: bool,
        scenario: u8,
        flags: u8,
        corrupt: bool,
        timestamp: Option<u32>,
        sequence_offset: u32,
    ) -> (std::string::String, Vec<(IpMetadata, Vec<u8>)>) {
        let mut cfg = config();
        cfg.reuse_time_wait = reuse;
        cfg.connection.timestamps = true;
        let (local, remote) = addresses();
        let tuple = Tuple {
            local: remote,
            remote: local,
        };
        let ip = IpMetadata {
            source: local.ip(),
            destination: remote.ip(),
        };
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
        let listener = (scenario != 0).then(|| b.listen(remote, 4).unwrap());
        let mut expected = None;
        if scenario == 2 {
            b.connect(0, remote, local).unwrap();
            packets(&mut b, 1_000);
            expected = Some(State::SynSent);
        } else if scenario >= 3 {
            let client = a.connect(0, local, remote).unwrap();
            if scenario == 3 {
                deliver(&mut b, 1_000, packets(&mut a, 1_000));
                expected = Some(State::SynReceived);
            } else {
                pump(&mut a, &mut b, 1_000);
                let server = b.accept(listener.unwrap()).unwrap();
                expected = Some(match scenario {
                    4 => State::Established,
                    5 => {
                        b.shutdown(server).unwrap();
                        packets(&mut b, 2_000);
                        State::FinWait1
                    }
                    6 => {
                        b.shutdown(server).unwrap();
                        pump(&mut a, &mut b, 2_000);
                        State::FinWait2
                    }
                    7 => {
                        a.shutdown(client).unwrap();
                        pump(&mut a, &mut b, 2_000);
                        State::CloseWait
                    }
                    8 => {
                        a.shutdown(client).unwrap();
                        pump(&mut a, &mut b, 2_000);
                        b.shutdown(server).unwrap();
                        packets(&mut b, 3_000);
                        State::LastAck
                    }
                    9 => {
                        a.shutdown(client).unwrap();
                        let fin = packets(&mut a, 2_000);
                        b.shutdown(server).unwrap();
                        packets(&mut b, 2_000);
                        deliver(&mut b, 3_000, fin);
                        State::Closing
                    }
                    10 => {
                        b.abort(server).unwrap();
                        State::Closed
                    }
                    _ => unreachable!(),
                });
                assert_eq!(b.state(server).unwrap(), expected.unwrap());
            }
        }
        let old = b.connection_id(tuple);
        if let Some(state) = expected.filter(|state| *state != State::Closed) {
            assert_eq!(b.state(old.unwrap()), Ok(state));
        }
        packets(&mut b, 3_000);
        let h = wire::Header {
            source_port: remote.port(),
            destination_port: local.port(),
            sequence: 0,
            acknowledgment: 0,
            flags: 0,
            window: 1024,
            urgent_pointer: 0,
        };
        let seq = old
            .map_or(100, |id| b.send_progress(id).unwrap().next_write_sequence)
            .wrapping_add(sequence_offset);
        let mut syn = tw_segment_with_payload(
            ip,
            h,
            seq,
            0,
            flags,
            timestamp.map(|value| (value, 0)),
            b"data",
        );
        if corrupt {
            syn[16] ^= 1;
        }
        let result = b.input(4_000, ip, &syn);
        let current = b.connection_id(tuple);
        let snapshot = std::format!(
            "{:?}",
            (
                result,
                current,
                b.buffer_bytes(),
                b.next_deadline(),
                current.map(|id| (
                    b.state(id),
                    b.transport_info(id),
                    b.received_ipv4_options(id)
                ))
            )
        );
        (snapshot, packets(&mut b, 4_000))
    }
    // The reuse heuristics' inputs vary too: no Timestamps option, and a
    // timestamp and a sequence number in each serial half-space from any
    // frontier the connection holds, so one of each is newer and one older.
    for scenario in 0..=10 {
        for flags in [
            wire::SYN,
            wire::SYN | wire::PSH | wire::URG | wire::FIN,
            wire::SYN | wire::ACK,
            wire::SYN | wire::RST,
        ] {
            for corrupt in [false, true] {
                for timestamp in [None, Some(99), Some(99 + (1 << 31))] {
                    for sequence_offset in [0, 1 << 31] {
                        assert_eq!(
                            observe(false, scenario, flags, corrupt, timestamp, sequence_offset),
                            observe(true, scenario, flags, corrupt, timestamp, sequence_offset),
                            "scenario={scenario} flags={flags} corrupt={corrupt} \
                             timestamp={timestamp:?} sequence_offset={sequence_offset}"
                        );
                    }
                }
            }
        }
    }
    // ACK/RST-bearing segments in TIME-WAIT are not new passive requests.
    for flags in [wire::SYN | wire::ACK, wire::SYN | wire::RST] {
        let mut results = Vec::new();
        for reuse in [false, true] {
            let mut cfg = config();
            cfg.reuse_time_wait = reuse;
            // The shared fixture enables reuse; create ordinary closing peers here.
            let (local, remote) = addresses();
            let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
            let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
            let listener = b.listen(remote, 4).unwrap();
            let client = a.connect(0, local, remote).unwrap();
            pump(&mut a, &mut b, 1_000);
            let old = b.accept(listener).unwrap();
            b.shutdown(old).unwrap();
            pump(&mut a, &mut b, 2_000);
            a.shutdown(client).unwrap();
            deliver(&mut b, 3_000, packets(&mut a, 3_000));
            let output = packets(&mut b, 3_000);
            let h = wire::parse(output[0].0, &output[0].1).unwrap().header;
            let ip = IpMetadata {
                source: local.ip(),
                destination: remote.ip(),
            };
            let syn =
                tw_segment_with_payload(ip, h, h.acknowledgment, h.sequence, flags, None, b"data");
            let result = b.input(4_000, ip, &syn);
            results.push((
                result,
                b.state(old),
                b.connection_id(Tuple {
                    local: remote,
                    remote: local,
                }),
                b.buffer_bytes(),
                b.next_deadline(),
                packets(&mut b, 4_000),
            ));
        }
        assert_eq!(results[0], results[1]);
    }
}

// The (time, TSval) pairs of the packets one side sent.
fn sent_timestamps(now: u64, packets: &[(IpMetadata, Vec<u8>)]) -> Vec<(u64, u32)> {
    packets
        .iter()
        .map(|(ip, bytes)| {
            let segment = wire::parse(*ip, bytes).unwrap();
            (now, segment.options.timestamps.unwrap().0)
        })
        .collect()
}

fn exchange(a: &mut Endpoint, b: &mut Endpoint, now: u64, sent: &mut Vec<(u64, u32)>) {
    for _ in 0..128 {
        let ab = packets(a, now);
        let ba = packets(b, now);
        if ab.is_empty() && ba.is_empty() {
            return;
        }
        sent.extend(sent_timestamps(now, &ba));
        deliver(b, now, ab);
        deliver(a, now, ba);
    }
    panic!("unexpected infinite packet exchange");
}

//= https://www.rfc-editor.org/rfc/rfc6191#section-1
//= type=test
//= reason=Native transport ticks come from the characterized CLOCK_BOOTTIME provider, which rejects decreasing samples. Endpoint::check_clock refuses earlier input and timestamp half-range jumps, every TSval is the selected tick plus one constant per-connection offset, and TIME-WAIT reuse inherits the old incarnation's offset, so a reincarnation continues its predecessor's timestamp clock. Embedders supplying their own clock own its monotonicity.
//# For the purpose of PAWS, the timestamps sent on a connection are
//# required to be monotonically increasing.
#[test]
fn timestamps_sent_on_a_connection_and_its_reincarnation_never_decrease() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.reuse_time_wait = true;
    let (local, remote) = addresses();
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    let mut sent = Vec::new();
    exchange(&mut a, &mut b, 1_000, &mut sent);
    let server = b.accept(listener).unwrap();
    // Sub-tick, single-tick and long steps of the millisecond cadence.
    for (i, now) in [1_400, 2_000, 2_999, 3_000, 10_000, 10_001, 500_000]
        .into_iter()
        .enumerate()
    {
        b.write(server, &[i as u8; 100]).unwrap();
        a.write(client, &[i as u8; 30]).unwrap();
        exchange(&mut a, &mut b, now, &mut sent);
    }
    // Earlier input is refused before it can reach the connection.
    a.write(client, b"x").unwrap();
    let late = packets(&mut a, 500_000);
    assert_eq!(
        b.input(499_999, ip, &late[0].1),
        Err(EndpointError::Connection(Error::TimeWentBackwards))
    );
    assert_eq!(
        b.poll_transmit(499_999, &mut [0; 2048], 16),
        Err(EndpointError::Connection(Error::TimeWentBackwards))
    );
    deliver(&mut b, 500_000, late);
    b.shutdown(server).unwrap();
    exchange(&mut a, &mut b, 600_000, &mut sent);
    a.shutdown(client).unwrap();
    let fin = packets(&mut a, 700_000);
    let peer = wire::parse(fin[0].0, &fin[0].1).unwrap().options.timestamps.unwrap().0;
    deliver(&mut b, 700_000, fin);
    sent.extend(sent_timestamps(700_000, &packets(&mut b, 700_000)));
    assert_eq!(b.state(server), Ok(State::TimeWait));
    // A fresher request reincarnates the connection on the same clock.
    let h = wire::Header {
        source_port: remote.port(),
        destination_port: local.port(),
        sequence: 0,
        acknowledgment: 0,
        flags: 0,
        window: 1024,
        urgent_pointer: 0,
    };
    let syn = tw_segment_with_payload(ip, h, 7, 0, wire::SYN, Some((peer + 1, 0)), b"");
    b.input(800_000, ip, &syn).unwrap();
    let new = b.connection_id(Tuple {
        local: remote,
        remote: local,
    });
    assert!(new.is_some_and(|id| id != server));
    assert_eq!(b.state(new.unwrap()), Ok(State::SynReceived));
    let synack = sent_timestamps(800_000, &packets(&mut b, 800_000));
    assert_eq!(synack.len(), 1);
    sent.extend(synack);
    assert!(sent.len() > 10);
    let offset = sent[0].1.wrapping_sub((sent[0].0 / 1_000) as u32);
    for (at, value) in &sent {
        assert_eq!(value.wrapping_sub((at / 1_000) as u32), offset, "at {at}");
    }
    for pair in sent.windows(2) {
        assert!(pair[1].1.wrapping_sub(pair[0].1) < 1 << 31, "{pair:?}");
    }
    assert_eq!(sent.last().unwrap().1.wrapping_sub(sent[0].1), 799);
}

#[test]
fn data_syn_allocation_failure_keeps_old_owner_and_candidate_timeout_frees_the_tuple() {
    for failure in 0..2 {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        cfg.connection.user_timeout_us = 180_000_000;
        let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
        let tuple = Tuple {
            local: addresses().1,
            remote: addresses().0,
        };
        let baseline = b.buffer_bytes();
        let deadline = b.next_deadline();
        b.set_listener_rx_timestamp_capacity(listener, 3).unwrap();
        let syn = tw_segment_with_payload(
            ip,
            h,
            h.acknowledgment,
            0,
            wire::SYN,
            Some((ts + 1, 0)),
            b"data",
        );
        if failure == 0 {
            crate::allocation_tests::fail_after(0, || {
                assert_eq!(
                    b.input_with_timestamps(4_000, ip, 0, Ipv4Options::default(), &syn, stamps(1)),
                    Ok(InputDisposition::Dropped)
                );
            });
            assert_eq!(b.connection_id(tuple), Some(old));
            assert_eq!(b.buffer_bytes(), baseline);
            assert_eq!(b.next_deadline(), deadline);
            assert!(packets(&mut b, 4_000).is_empty());
        }
        b.input_with_timestamps(5_000, ip, 0, Ipv4Options::default(), &syn, stamps(2))
            .unwrap();
        let child = b.connection_id(tuple).unwrap();
        assert_ne!(child, old);
        assert_eq!(b.state(child), Ok(State::SynReceived));
        packets(&mut b, 5_000);
        b.on_timeout(180_005_000, 64).unwrap();
        packets(&mut b, 180_005_000);
        // The candidate ended the old TIME-WAIT when it took the tuple.
        assert_eq!(b.connection_id(tuple), None);
        assert_eq!(b.state(old), Ok(State::Closed));
        assert_eq!(b.time_wait_connections(), 0);
        assert_eq!(b.buffer_bytes(), baseline);
        assert_eq!(b.next_deadline(), None);
        assert_eq!(
            b.accept(listener),
            Err(EndpointError::Connection(Error::WouldBlock))
        );
    }
}
