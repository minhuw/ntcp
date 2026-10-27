use super::*;

fn active_with_payload(tfo: bool, granularity: TimestampGranularity, offset: u32) -> Connection {
    let cfg = ConnectionConfig {
        timestamps: true,
        timestamp_granularity: granularity,
        sack: true,
        ..config(8192, 1000)
    };
    let mut a = Connection::active(tuple(), cfg, u32::MAX - 20, 0).unwrap();
    a.set_timestamp_offset(offset);
    if tfo {
        let mut cache = crate::fast_open::FastOpen::new().unwrap();
        cache.learn(
            0,
            tuple().local.ip(),
            tuple().remote.ip(),
            wire::FastOpenCookie::new(&[7; 8]).unwrap(),
            1000,
        );
        let cached = cache.get(0, 100, tuple().local.ip(), tuple().remote.ip());
        assert_eq!(a.prepare_fast_open(cached, b"request").unwrap(), 7);
    } else {
        assert_eq!(a.write(b"request").unwrap(), 7);
    }
    a
}

#[test]
fn syn_echo_invalid_does_not_commit_peer_state_and_valid_retry_delivers_once() {
    for tfo in [false, true] {
        for granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            for offset in [73, u32::MAX - 3] {
                for before_first in [false, true] {
                    let mut a = active_with_payload(tfo, granularity, offset);
                    let bytes = packet(&mut a, 2000);
                    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
                    let value = syn.options.timestamps.unwrap().0;
                    let ack = a.snd_nxt;
                    let deadline = a.rto_deadline;
                    let sample = a.sample;
                    let send_len = a.send.len();
                    let bad = if before_first {
                        value.wrapping_sub(1)
                    } else {
                        value.wrapping_add(1)
                    };
                    assert_ne!(bad, 0);
                    // An input later than the forged value must not authorize a
                    // timestamp that was never in the submitted SYN range.
                    timestamp_input(
                        &mut a,
                        20_000,
                        Seq(900),
                        ack,
                        SYN | ACK | FIN,
                        Some((600, bad)),
                        b"forged",
                    );
                    assert_eq!(a.state(), State::SynSent);
                    assert_eq!(a.irs, None);
                    assert!(!a.timestamps);
                    assert_eq!(a.snd_una, a.iss);
                    assert_eq!(a.send.len(), send_len);
                    assert_eq!(a.receive.readable(), 0);
                    assert!(!a.receive.eof());
                    assert_eq!(a.rto_deadline, deadline);
                    assert_eq!(a.sample, sample);
                    assert!(!a.handshake_complete());
                    assert!(!a.events_pending());
                    assert!(!a.fast_open_negative);
                    assert!(a.fast_open_learned.is_none());
                    let reset_bytes = packet(&mut a, 20_000);
                    let reset = wire::parse(ip(tuple()), &reset_bytes).unwrap();
                    assert_eq!(reset.header.flags, RST);
                    assert_eq!(reset.header.sequence, ack.0);
                    assert!(reset.options.timestamps.is_none());
                    assert_eq!(a.rto_deadline, deadline);
                    assert_eq!(a.syn_timestamp_range, Some((value, value)));
                    assert_eq!(a.transmit(20_000, &mut [0; 1500]), Ok(None));
                    timestamp_input(
                        &mut a,
                        21_000,
                        Seq(900),
                        ack,
                        SYN | ACK,
                        Some((601, value)),
                        b"ok",
                    );
                    assert_eq!(a.state(), State::Established);
                    assert!(a.handshake_complete());
                    assert_eq!(a.receive.readable(), 2);
                    assert_eq!(a.receive.next(), Seq(903));
                    assert_eq!(a.acknowledged, if tfo { 7 } else { 0 });
                    assert!(!a.fast_open_negative);
                }
            }
        }
    }
}

#[test]
fn syn_echo_original_and_retransmitted_bounds_are_inclusive_through_wrap() {
    for tfo in [false, true] {
        for granularity in [
            TimestampGranularity::Milliseconds,
            TimestampGranularity::Microseconds,
        ] {
            for use_retry in [false, true] {
                let offset = match granularity {
                    TimestampGranularity::Milliseconds => u32::MAX - 100,
                    TimestampGranularity::Microseconds => u32::MAX - 20_000,
                };
                let mut a = active_with_payload(tfo, granularity, offset);
                let first_bytes = packet(&mut a, 10_000);
                let first = wire::parse(ip(tuple()), &first_bytes)
                    .unwrap()
                    .options
                    .timestamps
                    .unwrap()
                    .0;
                let retry_at = a.rto_deadline.unwrap();
                a.timeout(retry_at).unwrap();
                let retry_bytes = packet(&mut a, retry_at);
                let last = wire::parse(ip(tuple()), &retry_bytes)
                    .unwrap()
                    .options
                    .timestamps
                    .unwrap()
                    .0;
                assert!(last < first, "timestamp wraps");
                assert_eq!(a.syn_timestamp_range, Some((first, last)));
                let ack = a.snd_nxt;
                timestamp_input(
                    &mut a,
                    retry_at + 1000,
                    Seq(900),
                    ack,
                    SYN | ACK,
                    Some((77, if use_retry { last } else { first })),
                    b"reply",
                );
                assert_eq!(a.state(), State::Established);
                assert_eq!(a.receive.readable(), 5);
                // A successful delayed SYNACK does not erase prior RTO evidence.
                assert_eq!(a.fast_open_negative, tfo);
            }
        }
    }
}

#[test]
fn syn_echo_selected_output_is_not_departure_and_uses_encoded_timestamp() {
    for tfo in [false, true] {
        let mut a = active_with_payload(tfo, TimestampGranularity::Milliseconds, 123);
        assert_eq!(a.transmit(1000, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!(a.syn_timestamp_range, None);
        let mut buf = [0; 1500];
        let n = a.transmit_selected(2000, &mut buf, true).unwrap().unwrap();
        let selected = wire::parse(ip(tuple()), &buf[..n]).unwrap();
        let value = selected.options.timestamps.unwrap().0;
        let count = selected.payload.len();
        let mut departure = a.last_departure.unwrap();
        assert_eq!(a.syn_timestamp_range, None);
        a.accept_reserved_output(50_000, &mut departure, 0, count, true)
            .unwrap();
        assert_eq!(a.syn_timestamp_range, Some((value, value)));
        assert_ne!(value, a.timestamp_value(50_000));
        let ack = a.snd_nxt;
        timestamp_input(
            &mut a,
            51_000,
            Seq(900),
            ack,
            SYN | ACK,
            Some((55, value)),
            b"ok",
        );
        assert_eq!(a.state(), State::Established);
    }
}

#[test]
fn syn_echo_rejected_retry_cannot_extend_previous_departure_range() {
    let mut a = active_with_payload(false, TimestampGranularity::Milliseconds, 123);
    packet(&mut a, 1000);
    let range = a.syn_timestamp_range;
    let retry_at = a.rto_deadline.unwrap();
    a.timeout(retry_at).unwrap();
    a.transmit_selected(retry_at, &mut [0; 1500], true)
        .unwrap()
        .unwrap();
    let unsubmitted = a.last_departure.unwrap().syn_timestamp.unwrap();
    a.reject_reserved_output();
    assert_eq!(a.syn_timestamp_range, range);
    let ack = a.snd_nxt;
    timestamp_input(
        &mut a,
        retry_at + 1000,
        Seq(900),
        ack,
        SYN | ACK,
        Some((55, unsubmitted)),
        b"bad",
    );
    assert_eq!(a.state(), State::SynSent);
    assert_eq!(a.receive.readable(), 0);
}

#[test]
fn syn_echo_missing_zero_and_unoffered_timestamps_remain_compatible() {
    for offered in [false, true] {
        for echo in [None, Some(0), Some(900_000)] {
            if offered && echo == Some(900_000) {
                continue;
            }
            let cfg = ConnectionConfig {
                timestamps: offered,
                ..config(128, 64)
            };
            let mut a = Connection::active(tuple(), cfg, 100, 0).unwrap();
            packet(&mut a, 1000);
            timestamp_input(
                &mut a,
                2000,
                Seq(900),
                Seq(101),
                SYN | ACK,
                echo.map(|e| (77, e)),
                b"ok",
            );
            assert_eq!(a.state(), State::Established);
            assert_eq!(a.timestamps, offered && echo.is_some());
            assert_eq!(a.receive.readable(), 2);
        }
    }
}

#[test]
fn syn_echo_does_not_gate_valid_resets_or_non_ack_simultaneous_open() {
    for flags in [RST | ACK, SYN] {
        let mut a = active_with_payload(false, TimestampGranularity::Milliseconds, 123);
        packet(&mut a, 1000);
        let ack = a.snd_nxt;
        timestamp_input(&mut a, 2000, Seq(900), ack, flags, Some((77, 900_000)), b"");
        if flags & RST != 0 {
            assert_eq!(a.state(), State::Closed);
            assert_eq!(a.close_reason(), Some(CloseReason::Reset));
        } else {
            assert_eq!(a.state(), State::SynReceived);
            assert_eq!(a.irs, Some(Seq(900)));
        }
    }
}
